package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// DKG counters
	DkgStarted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kosh_dkg_started_total",
		Help: "Total DKG sessions started.",
	})
	DkgCompleted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kosh_dkg_completed_total",
		Help: "Total DKG sessions completed successfully.",
	})
	DkgFailed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kosh_dkg_failed_total",
		Help: "Total DKG sessions that failed.",
	})

	// Signing counters
	SignStarted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kosh_sign_started_total",
		Help: "Total signing sessions started.",
	})
	SignCompleted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kosh_sign_completed_total",
		Help: "Total signing sessions completed successfully.",
	})
	SignFailed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kosh_sign_failed_total",
		Help: "Total signing sessions that failed.",
	})

	// Health gauge per service (1=up, 0=down)
	ServiceUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kosh_service_up",
		Help: "1 if the service is reachable, 0 otherwise.",
	}, []string{"service"})

	// Party phase gauge
	PartyPhase = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kosh_party_phase",
		Help: "Current phase index of each party daemon.",
	}, []string{"party"})

	// Coordinator bulletin board key count
	BbKeyCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kosh_bb_key_count",
		Help: "Number of keys currently in the bulletin board.",
	})
)

func Register() {
	prometheus.MustRegister(
		DkgStarted, DkgCompleted, DkgFailed,
		SignStarted, SignCompleted, SignFailed,
		ServiceUp, PartyPhase,
		BbKeyCount,
	)

	// Seed label-dimension gauges so they appear in /metrics from the start.
	for _, svc := range []string{"coordinator", "policy", "gateway", "party-1", "party-2", "party-3"} {
		ServiceUp.WithLabelValues(svc).Set(0)
	}
	for _, p := range []string{"party-1", "party-2", "party-3"} {
		PartyPhase.WithLabelValues(p).Set(0)
	}
}
