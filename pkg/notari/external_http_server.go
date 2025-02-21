package notari

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net/http"
	"time"
)

func StartExternalHttpServer(server Server, address string) {
	mux := http.NewServeMux()
	mux.Handle("/jwks.json", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		err := encoder.Encode(server.PublicJwks)
		if err != nil {
			server.Logger.Error().Err(err).Msg("error writing JWKS")
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	mux.Handle("/host_key", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(ssh.MarshalAuthorizedKey(server.HostKey.PublicKey()))
		if err != nil {
			server.Logger.Error().Err(err).Msg("failed to marshal authorized_keys")
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	httpServer := &http.Server{
		Addr:           address,
		Handler:        mux,
		ReadTimeout:    2 * time.Second,
		WriteTimeout:   2 * time.Second,
		MaxHeaderBytes: 100_000,
	}
	server.Logger.Info().Msg(fmt.Sprintf("starting external http server on %s", address))
	err := httpServer.ListenAndServe()
	if err != nil {
		server.Logger.Fatal().Err(err).Msg("failed to run external http server")
	}

}
