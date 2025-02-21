package notari

import (
	"fmt"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"time"
)

type TokenConfig struct {
	Key          jwk.Key
	Issuer       string
	StaticClaims map[string]string
	ClaimPrefix  string
	Expiry       time.Duration
}

func (config TokenConfig) ClaimName(name string) string {
	return fmt.Sprintf("%s%s", config.ClaimPrefix, name)
}

func GenerateToken(user *UserInfo, fingerprint string, config TokenConfig) (string, error) {
	iat := time.Now().UTC()
	tokenBuilder := jwt.NewBuilder()
	for key, value := range config.StaticClaims {
		tokenBuilder = tokenBuilder.Claim(config.ClaimName(key), value)
	}
	tokenBuilder.Issuer(config.Issuer).Subject(user.Sub).IssuedAt(iat).Expiration(iat.Add(1*time.Hour)).Claim(config.ClaimName("ssh_key_fingerprint"), fingerprint)
	for k, v := range user.Claims {
		tokenBuilder = tokenBuilder.Claim(config.ClaimName(k), v)
	}
	token, err := tokenBuilder.Build()
	if err != nil {
		return "", err
	}
	alg, _ := config.Key.Algorithm()
	signedToken, err := jwt.Sign(token, jwt.WithKey(alg, config.Key))
	return string(signedToken), nil
}
