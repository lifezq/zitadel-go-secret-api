/**
* PACKAGE main
* Name basic_auth_header_generate
* Description TODO
* Author yangqianlei@deltaphone.com.cn
* Date 2023/4/19
 */
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net/url"
)

var (
	clientId     = flag.String("client_id", "", "client id")
	clientSecret = flag.String("client_secret", "", "client secret")
)

func main() {
	flag.Parse()

	if clientId == nil || clientSecret == nil {
		flag.PrintDefaults()
		return
	}

	fmt.Printf("Authorization: Basic %s", base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s",
		url.QueryEscape(*clientId), url.QueryEscape(*clientSecret)))))
	//output:Authorization: Basic MjA2MzMzMzA0ODE3OTEwMDE3JTQwc3ByaW5nX2Jvb3Q6QzhsbHNwcTdZd3A4S1RpNmlhU2tPbHNqYlRNazU0a3F6d2c3b2dqeHB1QnJRejJ0b3RaMHh2VFFIUnBsVWx5Mw==
}
