package authorization

type JWT interface {
	IsValid() (bool, error)
}

type jwt struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

func (jwt *jwt) ParseClaims(token string) error {
	return nil
}

func (jwt *jwt) IsValid() (bool, error) {
	return true, nil
}

func NewJWT() JWT {
	return &jwt{}
}
