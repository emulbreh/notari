package notari

import "github.com/prometheus/client_golang/prometheus"

var Metrics = struct {
	SshRequestCounter            prometheus.Counter
	AuthenticationFailureCounter prometheus.Counter
}{
	SshRequestCounter: prometheus.NewCounter(prometheus.CounterOpts{
		Name: "seamless_ssh_requests",
	}),
	AuthenticationFailureCounter: prometheus.NewCounter(prometheus.CounterOpts{
		Name: "seamless_authentication_failure",
	}),
}
