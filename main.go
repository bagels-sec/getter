package main

import (
	"fmt"
	"flag"
	"os"
	"bufio"
	"time"
	"crypto/tls"
	"net/http"
	"encoding/json"
	"io/ioutil"
	"strings"
	"github.com/haccer/subjack/subjack"
)

func checkUp(domain string){
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
        client := http.Client{
                  Timeout: 1 * time.Second,
	  }
	response, err := client.Get("https://"+domain+"/")
	if err != nil {
		fmt.Println(domain + " Down")
	}
	if response != nil {
		switch response.StatusCode {
			case 200:
				jackit(domain)
				fmt.Println(domain, response.StatusCode, response.Header["Server"])
			case 404:
				jackit(domain)
				fmt.Println(domain, response.StatusCode, response.Header["Server"])
			case 403:
				jackit(domain)
				fmt.Println(domain, response.StatusCode, response.Header["Server"])
			case 500:
				jackit(domain)
				fmt.Println(domain, response.StatusCode, response.Header["Server"])
			case 301:
				jackit(domain)
				fmt.Println(domain, response.StatusCode, response.Header["Server"])
			case 302:
				jackit(domain)
				fmt.Println(domain, response.StatusCode, response.Header["Server"])
			case 400:
				jackit(domain)
				fmt.Println(domain, response.StatusCode, response.Header["Server"])
			default:
				fmt.Println(domain +" Down")
		}
	defer response.Body.Close()
}
}

func jackit(subdomain string){

var fingerprints []subjack.Fingerprints
	config, _ := ioutil.ReadFile("fingerprints.json")
	json.Unmarshal(config, &fingerprints)
	service := subjack.Identify(subdomain, false, false, 10, fingerprints)

	if service != "" {
		service = strings.ToLower(service)
		fmt.Printf("%s is pointing to a vulnerable %s service.\n", subdomain, service)
	}

}

func main(){

	var fpath = flag.String("d", "./domains.txt", "A List of Subdomains")
	flag.Parse()
	domainFile, err := os.Open(*fpath)
	if err != nil {
		fmt.Println(err)
	}

	scanner := bufio.NewScanner(domainFile)
	scanner.Split(bufio.ScanLines)
	var text []string
	for scanner.Scan(){
		text = append(text, scanner.Text())
	}
	for _, each_ln := range text {
		checkUp(each_ln)
	}
	domainFile.Close()
	fmt.Println(*fpath)
}
