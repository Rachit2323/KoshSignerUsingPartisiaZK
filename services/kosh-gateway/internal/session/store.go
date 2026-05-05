package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

type LinkedKey struct {
	ContractAddress string `json:"contract_address"`
	KeyID           uint32 `json:"key_id"`
	Label           string `json:"label"`
	CombinedPkHex   string `json:"combined_pk_hex"`
	EvmAddress      string `json:"evm_address"`
}

type Account struct {
	AccountID   string      `json:"account_id"`
	Label       string      `json:"label"`
	LinkedKeys  []LinkedKey `json:"linked_keys"`
	SelectedKey *LinkedKey  `json:"selected_key"`
}

type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Account // token → account
}

func New() *Store {
	return &Store{sessions: make(map[string]*Account)}
}

func (s *Store) NewToken(account *Account) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[tok] = account
	s.mu.Unlock()
	return tok, nil
}

func (s *Store) Get(token string) (*Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.sessions[token]
	return a, ok
}

func (s *Store) Update(token string, fn func(*Account)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.sessions[token]
	if !ok {
		return false
	}
	fn(a)
	return true
}
