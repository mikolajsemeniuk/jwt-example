package jwt2

import (
	jose "github.com/dvsekhvalnov/jose2go"
)

func CreateHS256Token(payload string, key []byte) (string, error) {
	token, err := jose.Sign(payload, jose.HS256, key)

	if err != nil {
		return "", err
	}

	return token, nil
}
