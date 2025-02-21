package notari

import (
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync"
)

const (
	UsernameKey    = "username"
	FingerprintKey = "pubkey-fp"
)

type Server struct {
	Provider    Provider
	HostKey     ssh.Signer
	Logger      zerolog.Logger
	Jwks        jwk.Set
	PublicJwks  jwk.Set
	TokenConfig TokenConfig
}

const (
	Ok          = 0
	ClientError = 1
	AuthError   = 2
	ServerError = 5
)

func (server *Server) authenticate(user *UserInfo, fingerprint string) error {
	for _, node := range user.Keys {
		server.Logger.Debug().Str("fingerprint", node.Fingerprint).Msg("checking key")
		if node.Fingerprint == fingerprint {
			return nil
		}
	}
	return errors.New("key doesn't match username")
}

func (server *Server) handleChannel(channel ssh.Channel, requests <-chan *ssh.Request, permissions *ssh.Permissions) {
	defer channel.Close()
	fingerprint := permissions.Extensions[FingerprintKey]
	username := permissions.Extensions[UsernameKey]
	logger := server.Logger.With().Str("username", username).Logger()
	errorCode := Ok
requestLoop:
	for req := range requests {
		switch req.Type {
		case "pty-req":
			// Pretend to support PTY requests to simplify client side command line options.
			req.Reply(true, nil)
			continue
		case "shell":
			// Treat "shell" like exec with an empty payload.
			fallthrough
		case "exec":
			if req.Payload != nil && len(req.Payload) > 4 {
				logger.Debug().Str("command", string(req.Payload[4:])).Msg("received shell command")
			}
			err := req.Reply(true, nil)
			if err != nil {
				logger.Printf("Error replying to %v request: %v", req.Type, err)
				errorCode = ClientError
				break requestLoop
			}
			user, err := server.Provider.GetUserInfo(username)
			err = server.authenticate(user, fingerprint)
			if err != nil {
				Metrics.AuthenticationFailureCounter.Inc()
				logger.Info().Err(err).Int("error_code", errorCode).Msg("authentication error")
				_, err := io.WriteString(channel.Stderr(), "Authentication failed for the given keys and username\n")
				if err != nil {
					logger.Debug().Err(err).Msg("failed to channel stderr")
				}
				errorCode = AuthError
				break requestLoop
			}

			logger.Info().Msg("authenticated successfully")
			token, err := GenerateToken(user, fingerprint, server.TokenConfig)
			if err != nil {
				logger.Error().Err(err).Msg("failed to generate token")
				errorCode = ServerError
				break requestLoop
			}

			_, err = io.WriteString(channel, token)
			if err != nil {
				logger.Error().Err(err).Msg("failed to write token")
			}
			break requestLoop
		case "env":
			// ignored
			req.Reply(false, nil)
		default:
			logger.Debug().Str("request_type", req.Type).Msg("ignoring unsupported request type")
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
	_, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(errorCode)}))

	if err != nil {
		logger.Info().Err(err).Msg("failed to send exist status")
	}
}

func (server *Server) handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	Metrics.SshRequestCounter.Inc()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		server.Logger.Info().Err(err).Msg("failed to handshake")
		return
	}
	defer sshConn.Close()

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		ssh.DiscardRequests(reqs)
		wg.Done()
	}()

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			server.Logger.Info().Str("channel_type", newChannel.ChannelType()).Msg("ignoring unsupported channel type")
			err := newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			if err != nil {
				server.Logger.Info().Err(err).Msg("failed to reject channel type")
			}
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			server.Logger.Error().Err(err).Msg("failed to accept channel")
			continue
		}
		wg.Add(1)
		go func() {
			server.handleChannel(channel, requests, sshConn.Permissions)
			wg.Done()
		}()
	}
}

func (server *Server) Start(address string) {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{
				Extensions: map[string]string{
					FingerprintKey: ssh.FingerprintSHA256(pubKey),
					"key":          string(ssh.MarshalAuthorizedKey(pubKey)),
					UsernameKey:    c.User(),
				},
			}, nil
		},
	}
	config.AddHostKey(server.HostKey)

	server.Logger.Info().Msg(fmt.Sprintf("listening on %s", address))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		server.Logger.Fatal().Err(err).Msg("failed to listen for connection")
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			server.Logger.Fatal().Err(err).Msg("failed to accept incoming connection")
		}
		go server.handleConnection(conn, config)
	}

}
