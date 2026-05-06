package bb

import (
	"context"

	pb "github.com/kosh/coordinator/pb"
)

// Server implements the BulletinBoard gRPC service.
type Server struct {
	pb.UnimplementedBulletinBoardServer
	store *Store
}

func NewServer() *Server {
	return &Server{store: NewStore()}
}

func (s *Server) Post(_ context.Context, req *pb.PostRequest) (*pb.PostResponse, error) {
	s.store.Post(req.Topic, req.Value)
	return &pb.PostResponse{Ok: true}, nil
}

func (s *Server) Read(_ context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error) {
	v, found := s.store.Read(req.Topic)
	return &pb.ReadResponse{Value: v, Found: found}, nil
}

// Watch streams the current value immediately (if set), then streams every future
// update until the client disconnects. Each client gets its own goroutine (gRPC handles this).
func (s *Server) Watch(req *pb.WatchRequest, stream pb.BulletinBoard_WatchServer) error {
	topic := req.Topic

	// If a value already exists, send it immediately so the client doesn't wait.
	if val, ok := s.store.Read(topic); ok {
		if err := stream.Send(&pb.WatchEvent{Topic: topic, Value: val}); err != nil {
			return err
		}
	}

	// Subscribe to future updates for this topic.
	ch := s.store.Subscribe(topic)
	defer s.store.Unsubscribe(topic, ch)

	for {
		select {
		case val, open := <-ch:
			if !open {
				// Channel closed by Clear() — this Watch subscription is cancelled.
				return nil
			}
			if err := stream.Send(&pb.WatchEvent{Topic: topic, Value: val}); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (s *Server) Clear(_ context.Context, _ *pb.ClearRequest) (*pb.ClearResponse, error) {
	n := s.store.Clear()
	return &pb.ClearResponse{KeysCleared: int32(n)}, nil
}

func (s *Server) List(_ context.Context, _ *pb.ListRequest) (*pb.ListResponse, error) {
	return &pb.ListResponse{Topics: s.store.List()}, nil
}
