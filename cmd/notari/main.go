package main

import (
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
	"notari/pkg/notari"
	"os"
	"time"
)

var logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

func pickSigningKey(jwks jwk.Set, kid string) (jwk.Key, error) {
	if kid != "" {
		signingKey, found := jwks.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("JWKS does not contain a key with kid '%s'", kid)
		}
		return signingKey, nil
	} else if jwks.Len() == 1 {
		signingKey, _ := jwks.Key(0)
		return signingKey, nil
	} else {
		return nil, fmt.Errorf("JWKS does not contain exactly one key and no kid was specified")
	}
}

func main() {
	var cli struct {
		HostKeyPath         string `type:"string" env:"NOTARI_HOST_KEY_PATH"`
		LogLevel            string `type:"string" env:"NOTARI_LOG_LEVEL" default:"info"`
		Address             string `type:"string" env:"NOTARI_ADDRESS" default:"0.0.0.0:1022"`
		GithubToken         string `type:"string" env:"NOTARI_GITHUB_TOKEN,GITHUB_TOKEN" default:""`
		ExternalHttpAddress string `type:"string" env:"NOTARI_EXTERNAL_HTTP_ADDRESS" default:""`
		InternalHttpAddress string `type:"string" env:"NOTARI_INTERNAL_HTTP_ADDRESS" default:""`
		JwksPath            string `type:"string" env:"NOTARI_JWKS_PATH" default:""`
		JwkKid              string `type:"string" env:"NOTARI_JWK_KID"`
		Issuer              string `type:"string" env:"NOTARI_ISSUER" default:"notari"`
		ClaimPrefix         string `type:"string" env:"NOTARI_CLAIM_PREFIX" default:"notari:"`
		ExpirySeconds       uint   `type:"uint" env:"NOTARI_EXPIRY_SECONDS" default:"3600"`
	}

	kong.Parse(&cli)

	logLevel, err := zerolog.ParseLevel(cli.LogLevel)
	if err != nil {
		logger.Fatal().Err(err).Msg("invalid log level")
		os.Exit(1)
	}
	zerolog.SetGlobalLevel(logLevel)

	hostKey, err := notari.SetupHostKey(cli.HostKeyPath, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to setup host key")
		os.Exit(2)
	}
	logger.Info().Msg(fmt.Sprintf("host key fingerprint: %s", ssh.FingerprintSHA256(hostKey.PublicKey())))

	jwks, publicJwks, err := notari.SetupJWKS(cli.JwksPath, cli.JwkKid, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to setup JWKS")
		os.Exit(2)
	}

	signingKey, err := pickSigningKey(jwks, cli.JwkKid)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to pick signing key")
		os.Exit(2)
	}

	provider := notari.NewCachingProvider(notari.NewGithubProvider(cli.GithubToken))

	server := notari.Server{
		Provider:   provider,
		HostKey:    hostKey,
		Logger:     logger,
		Jwks:       jwks,
		PublicJwks: publicJwks,
		TokenConfig: notari.TokenConfig{
			Issuer:       cli.Issuer,
			Key:          signingKey,
			ClaimPrefix:  cli.ClaimPrefix,
			StaticClaims: map[string]string{},
			Expiry:       time.Duration(cli.ExpirySeconds) * time.Second,
		},
	}
	
	if cli.InternalHttpAddress != "" {
		go notari.StartInternalHttpServer(server, cli.InternalHttpAddress)
	}
	if cli.ExternalHttpAddress != "" {
		go notari.StartExternalHttpServer(server, cli.ExternalHttpAddress)
	}
	server.Start(cli.Address)
}
