// Example tool to determine the keysize being used
// from the Hacked Server.
package main

import (
	"net/url"
	"net/http"
	"net/http/cookiejar"
	"encoding/base64"
	"log"
	"fmt"
)

func getProfileLen(client http.Client, data string) int {
	u, _ := url.Parse("http://localhost:8080/profile?email=" + data)
	client.Get(u.String())
	for _, cookie := range(client.Jar.Cookies(u)) {
		if cookie.Name == "profile" {
			decoded, err := base64.StdEncoding.DecodeString(cookie.Value)
			if err != nil {
				panic(err)
			}
			return len(decoded)
		}
	}
	return 0
}

func main() {
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	client := http.Client{Jar: jar}

	// We'll just keep sending longer data until the encrypted profile jumps in size
	email := "A"
	prevLen := getProfileLen(client, email)
	keysize := 0
	for i := 0; i < 48; i++ {
		email += "A"
		newLen := getProfileLen(client, email)
		if newLen - prevLen > 1 {
			keysize = newLen - prevLen
			break
		}

		prevLen = newLen
	}
	fmt.Println("Keysize:", keysize)
}
