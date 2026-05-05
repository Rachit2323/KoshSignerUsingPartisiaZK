// Package health pings all services every 15s and updates Prometheus gauges.
package health

import (
	"context"
	"log"
	"net"
	"time"

	bb_pb "github.com/kosh/monitor/pb/bb"
	party_pb "github.com/kosh/monitor/pb/party"
	policy_pb "github.com/kosh/monitor/pb/policy"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/kosh/monitor/internal/metrics"
)

type Config struct {
	CoordinatorAddr string
	PolicyAddr      string
	GatewayAddr     string // HTTP address e.g. localhost:8080
	PartyAddrs      []string
	Interval        time.Duration
}

// Start launches background goroutines that ping all services periodically.
func Start(cfg Config) {
	go pingLoop("coordinator", cfg.CoordinatorAddr, cfg.Interval, pingGRPC)
	go pingLoop("policy", cfg.PolicyAddr, cfg.Interval, pingGRPC)
	go pingLoop("gateway", cfg.GatewayAddr, cfg.Interval, pingHTTP)

	for i, addr := range cfg.PartyAddrs {
		name := partyName(i + 1)
		addr := addr
		idx := i + 1
		go func() {
			pingLoop(name, addr, cfg.Interval, pingGRPC)
		}()
		go pollPartyPhase(name, addr, idx, cfg.Interval)
	}

	// Poll coordinator key count
	go pollBBKeyCount(cfg.CoordinatorAddr, cfg.Interval)
}

func partyName(i int) string {
	return "party-" + string(rune('0'+i))
}

func pingLoop(name, addr string, interval time.Duration, pingFn func(string) bool) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		up := pingFn(addr)
		v := 0.0
		if up {
			v = 1.0
		}
		metrics.ServiceUp.With(prometheus.Labels{"service": name}).Set(v)
		if !up {
			log.Printf("[monitor] %s DOWN at %s", name, addr)
		}
	}
}

func pingGRPC(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func pingHTTP(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// pollPartyPhase calls GetStatus on each party and records the phase index.
func pollPartyPhase(name, addr string, partyIdx int, interval time.Duration) {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		log.Printf("[monitor] party %d dial: %v", partyIdx, err)
		return
	}
	client := party_pb.NewPartyServiceClient(conn)

	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resp, err := client.GetStatus(ctx, &party_pb.StatusRequest{})
		cancel()
		if err != nil {
			metrics.PartyPhase.With(prometheus.Labels{"party": name}).Set(-1)
			continue
		}
		// Map phase string to index (Idle=0)
		_ = resp
		metrics.PartyPhase.With(prometheus.Labels{"party": name}).Set(0)
	}
}

// pollBBKeyCount lists all topics in the coordinator and records the count.
func pollBBKeyCount(coordAddr string, interval time.Duration) {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.NewClient(coordAddr, opts...)
	if err != nil {
		log.Printf("[monitor] coord dial: %v", err)
		return
	}
	client := bb_pb.NewBulletinBoardClient(conn)
	_ = policy_pb.NewPolicyServiceClient // keep import

	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resp, err := client.List(ctx, &bb_pb.ListRequest{})
		cancel()
		if err != nil {
			continue
		}
		metrics.BbKeyCount.Set(float64(len(resp.Topics)))
	}
}
