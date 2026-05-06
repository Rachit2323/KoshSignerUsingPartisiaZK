package bb

import "sync"

// Store is a thread-safe key-value bulletin board with pub-sub per topic.
type Store struct {
	mu   sync.RWMutex
	data map[string]string
	subs map[string][]chan string
}

func NewStore() *Store {
	return &Store{
		data: make(map[string]string),
		subs: make(map[string][]chan string),
	}
}

// Post stores a value and notifies all active Watch subscribers for that topic.
func (s *Store) Post(topic, value string) {
	s.mu.Lock()
	s.data[topic] = value
	listeners := make([]chan string, len(s.subs[topic]))
	copy(listeners, s.subs[topic])
	s.mu.Unlock()

	// Broadcast outside the lock to avoid deadlock
	for _, ch := range listeners {
		select {
		case ch <- value:
		default:
		}
	}
}

// Read returns the current value for a topic (non-blocking).
func (s *Store) Read(topic string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[topic]
	return v, ok
}

// Subscribe registers a new subscriber channel for a topic.
// The channel receives values whenever Post is called for that topic.
func (s *Store) Subscribe(topic string) chan string {
	ch := make(chan string, 8)
	s.mu.Lock()
	s.subs[topic] = append(s.subs[topic], ch)
	s.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel for a topic.
func (s *Store) Unsubscribe(topic string, ch chan string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.subs[topic]
	for i, c := range list {
		if c == ch {
			s.subs[topic] = append(list[:i], list[i+1:]...)
			close(ch)
			return
		}
	}
}

// Clear wipes all data AND closes all subscriber channels so stale Watch
// goroutines exit. Returns number of keys removed.
func (s *Store) Clear() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.data)
	s.data = make(map[string]string)
	for _, chans := range s.subs {
		for _, ch := range chans {
			close(ch)
		}
	}
	s.subs = make(map[string][]chan string)
	return n
}

// List returns all topics that have a value.
func (s *Store) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	topics := make([]string, 0, len(s.data))
	for t := range s.data {
		topics = append(topics, t)
	}
	return topics
}
