package notari

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
	"os"
)

func loadHostKey(path string) (ssh.Signer, error) {
	hostKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load host key from %s: %w", path, err)
	}
	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key: %w", err)
	}
	return hostKey, nil
}

func generateHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}
	return ssh.NewSignerFromKey(key)
}

func SetupHostKey(hostKeyPath string, logger zerolog.Logger) (ssh.Signer, error) {
	if hostKeyPath != "" {
		logger.Info().Msg(fmt.Sprintf("loading host key from '%s'", hostKeyPath))
		return loadHostKey(hostKeyPath)
	}
	logger.Info().Msg("no host key configured, a new key will be generated")
	return generateHostKey()
}
