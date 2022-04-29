package jwt1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func Encode(data []byte) string {
	result := base64.StdEncoding.EncodeToString(data)
	result = strings.Replace(result, "+", "-", -1)
	result = strings.Replace(result, "/", "_", -1)
	result = strings.Replace(result, "=", "", -1)

	return result
}

func CreateHS256Token(payload string, key []byte) (string, error) {
	h := hmac.New(sha256.New, []byte(key))
	header := `{ "alg": "HS256" }`
	header64 := Encode([]byte(header))

	payload64 := Encode([]byte(payload))

	message := header64 + "." + payload64

	unsignedStr := header + payload

	h.Write([]byte(unsignedStr))
	signature := Encode(h.Sum(nil))

	tokenStr := message + "." + signature
	return tokenStr, nil
}

func Decode(data string) ([]byte, error) {
	data = strings.Replace(data, "-", "+", -1) // 62nd char of encoding
	data = strings.Replace(data, "_", "/", -1) // 63rd char of encoding

	switch len(data) % 4 { // Pad with trailing '='s
	case 0: // no padding
	case 2:
		data += "==" // 2 pad chars
	case 3:
		data += "=" // 1 pad char
	}

	return base64.StdEncoding.DecodeString(data)
}

func ValidateToken(token string, secret []byte) (bool, error) {
	parts := strings.Split(token, ".")
	data := parts[0] + "." + parts[1]
	claims := map[string]interface{}{}
	byteParts := [3][]byte{}

	for index, part := range parts {
		bytes, err := Decode(part)
		if err != nil {
			return false, err
		}
		byteParts[index] = bytes
	}

	err := json.Unmarshal(byteParts[1], &claims)
	if err != nil {
		return false, err
	}

	hasher := hmac.New(sha256.New, secret)
	_, err = hasher.Write([]byte(data))
	if err != nil {
		return false, err
	}
	signature := hasher.Sum(nil)

	if !hmac.Equal(signature, byteParts[2]) {
		return false, fmt.Errorf("invalid signature")
	}

	return true, nil
}
