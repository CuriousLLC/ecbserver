package main

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"log"
	"fmt"
)

const keysize = 16

var key []byte = RandomKey(keysize)

func SecretPhrase(w http.ResponseWriter, r *http.Request) {
        unknown := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\n" +
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\n" +
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\n" +
                "YnkK"

	getVars, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		panic(err)
	}

	data := getVars.Get("input")
	fmt.Println("Input:", data)
        decoded, _ := base64.StdEncoding.DecodeString(unknown)
        amended := append([]byte(data), decoded...)
        padded := AddPadding(amended, keysize)

        w.Write(ECBEncrypt(key, padded))
}

func CreateSession(w http.ResponseWriter, r *http.Request) {
	getVars, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		panic(err)
	}

	email := getVars.Get("email")
	profile := url.Values{}
	profile.Set("email", email)
	profile.Set("uid", "10")
	profile.Set("zole", "user")

	padded := AddPadding([]byte(profile.Encode()), keysize)
	encoded := base64.StdEncoding.EncodeToString(ECBEncrypt(key, padded))
	cookie := &http.Cookie{Name: "profile", Value: encoded}
	http.SetCookie(w, cookie)
	w.Write([]byte("Created"))
}

func GetSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("profile")
	if err != nil {
		fmt.Println("Cookie not set")
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		panic(err)
	}

	profile := ECBDecrypt(key, decoded)
	stripped := StripPadding(profile)
	w.Write(stripped)
}

func main() {
	http.HandleFunc("/secret", SecretPhrase)
	http.HandleFunc("/profile", CreateSession)
	http.HandleFunc("/verify", GetSession)

	fmt.Println("Waiting for connections...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
