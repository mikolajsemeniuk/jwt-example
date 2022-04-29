package main

import (
	"fmt"
	"os"

	jose "github.com/dvsekhvalnov/jose2go"
	"github.com/mikolajsemeniuk/jwt/jwt1"
	"github.com/mikolajsemeniuk/jwt/jwt2"
)

func main() {
	payload := `{ "one": 1 }`
	key := []byte("super_secret_key")

	token1, err := jwt1.CreateHS256Token(payload, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	token2, err := jwt2.CreateHS256Token(payload, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("token1: ", token1)
	fmt.Println("token2: ", token2)

	payload1, headers, err := jose.Decode(token2, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("\npayload = %v\n", payload1)
	fmt.Printf("\nheaders = %v\n", headers)

	payload2, err := jwt1.ValidateToken(token2, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("payload2: ", payload2)
}
