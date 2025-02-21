package notari

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rs/zerolog"
	"os"
)

func loadKey(jwksPath string) (jwk.Set, error) {
	f, err := os.Open(jwksPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load JWKS from %s: %w", jwksPath, err)
	}
	set, err := jwk.ParseReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}
	return set, nil
}

func generateKey(kid string) (jwk.Set, error) {
	rsa_key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	set := jwk.NewSet()

	private_key, err := jwk.Import(rsa_key)
	if err != nil {
		return nil, fmt.Errorf("failed to create private JWK: %w", err)
	}
	err = private_key.Set("alg", jwa.RS256())
	if err != nil {
		return nil, err
	}
	err = private_key.Set("kid", kid)
	if err != nil {
		return nil, err
	}
	err = set.AddKey(private_key)
	if err != nil {
		return nil, err
	}

	json, _ := json.MarshalIndent(private_key, "", "  ")
	fmt.Println(string(json)) // FIXME

	return set, nil
}

func SetupJWKS(jwksPath string, defaultKeyId string, logger zerolog.Logger) (jwk.Set, jwk.Set, error) {
	var privateKeySet jwk.Set
	var err error
	if jwksPath == "" {
		logger.Info().Msg("Generating new signing JWKS")
		privateKeySet, err = generateKey(defaultKeyId)
	} else {
		logger.Info().Msg(fmt.Sprintf("loading signing JWKS from '%s'", jwksPath))
		privateKeySet, err = loadKey(jwksPath)
		if err != nil {
			return nil, nil, err
		}
	}
	publicKeySet, err := jwk.PublicSetOf(privateKeySet)
	if err != nil {
		return nil, nil, err
	}
	return privateKeySet, publicKeySet, nil
}
