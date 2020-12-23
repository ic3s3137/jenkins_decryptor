package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
)
//var BapSshPublisherPluginTemplate = "jenkins.+?BapSshHostConfiguration.+?jenkins.+?BapSshHostConfiguration"
var BapSshPublisherPluginTemplate = "(?s:<jenkins\\.plugins.+?BapSshHostConfiguration.*?>" +
	".*?<hostname>(.*?)</hostname>.*?" +
	".*?<username>(.*?)</username>.*?" +
	".*?<keyInfo>.+?<secretPassphrase>\\{?(.*?)\\}?</secretPassphrase>.*?</keyInfo>.*?"+
	"</jenkins\\.plugins.+?BapSshHostConfiguration>)"//\\s+<name>(.+?)</name>/"

var CredentialsTemplate = "(?s:<username>(.*?)</username>.*?<(password|privateKey)>\\{?(.*?)\\}?</(password|privateKey)>)"

func main(){

	if len(os.Args) != 4{
		fmt.Println(os.Args[0],"<master.key> <hudson.util.Secret> <credentials.xml/jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml>")
		os.Exit(1)
	}
	masterPath := os.Args[1]
	HudsonSecretPath := os.Args[2]
	xmlPath := os.Args[3]
	masterKey,err := ioutil.ReadFile(masterPath)
	if err != nil{
		log.Fatalln(err)
	}
	HudsonSecret,err := ioutil.ReadFile(HudsonSecretPath)
	if err != nil{
		log.Fatalln(err)
	}
	xmlContent ,err := ioutil.ReadFile(xmlPath)
	if err != nil{
		log.Fatalln(err)
	}
	secret := DecryptHudsonSecret(masterKey,HudsonSecret)

	//passwordStr := "AQAAABAAAAAQTb1+tcGnYS3D6fX3xbrgL9ZKd+m6n2G5GISfdtTghkY="
	//clear := DecryptSecretPassphrase(passwordStr,secret)
	//fmt.Println(clear)

	BapSshPublisherPluginRegx := regexp.MustCompile(BapSshPublisherPluginTemplate)
	matches1 := BapSshPublisherPluginRegx.FindAllSubmatch(xmlContent,-1)
	credentialRegx := regexp.MustCompile(CredentialsTemplate)
	matches2 := credentialRegx.FindAllSubmatch(xmlContent,-1)
	if len(matches1) > 0{
		for _,n := range matches1{
			hostname := string(n[1])
			username := string(n[2])
			password := string(n[3])
			//fmt.Println(password)
			clearPass := DecryptSecret(password,secret)
			fmt.Println("hostname:",hostname,"username:",username,"password:",clearPass)
			//fmt.Println(,string(n[2]),string(n[3]))
		}
	}else if len(matches2) > 0 {
		for _,n := range matches2{
			username := string(n[1])
			password := string(n[3])
			//fmt.Println(username)
			//os.Exit(1)
			clearPass := DecryptSecret(password,secret)
			fmt.Println("username:",username,"password:",clearPass)
		}
	}
}
