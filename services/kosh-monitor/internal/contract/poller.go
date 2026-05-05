// Package contract polls the Partisia blockchain for contract state every 30s.
package contract

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type ContractState struct {
	Address   string         `json:"address"`
	RawState  map[string]any `json:"state"`
	FetchedAt time.Time      `json:"fetched_at"`
}

type Poller struct {
	nodeURL         string
	contractAddress string
	interval        time.Duration
	onUpdate        func(ContractState)
}

func NewPoller(nodeURL, contractAddress string, interval time.Duration, onUpdate func(ContractState)) *Poller {
	return &Poller{nodeURL: nodeURL, contractAddress: contractAddress, interval: interval, onUpdate: onUpdate}
}

// Start polls the contract state in the background.
func (p *Poller) Start() {
	go func() {
		t := time.NewTicker(p.interval)
		defer t.Stop()
		for range t.C {
			state, err := p.fetch()
			if err != nil {
				log.Printf("[monitor] contract poll error: %v", err)
				continue
			}
			if p.onUpdate != nil {
				p.onUpdate(*state)
			}
		}
	}()
}

func (p *Poller) fetch() (*ContractState, error) {
	url := fmt.Sprintf("%s/blockchain/contracts/%s", p.nodeURL, p.contractAddress)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return &ContractState{
		Address:   p.contractAddress,
		RawState:  raw,
		FetchedAt: time.Now(),
	}, nil
}
