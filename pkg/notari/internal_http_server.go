package notari

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"time"
)

func StartInternalHttpServer(server Server, address string) {
	prometheus.MustRegister(Metrics.SshRequestCounter)
	prometheus.MustRegister(Metrics.AuthenticationFailureCounter)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/livez", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mux.Handle("/readyz", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	httpServer := &http.Server{
		Addr:           address,
		Handler:        mux,
		ReadTimeout:    2 * time.Second,
		WriteTimeout:   2 * time.Second,
		MaxHeaderBytes: 100_000,
	}
	server.Logger.Info().Msg(fmt.Sprintf("starting internal http server on %s", address))
	err := httpServer.ListenAndServe()
	if err != nil {
		server.Logger.Fatal().Err(err).Msg("failed to run internal http server")
	}
}
