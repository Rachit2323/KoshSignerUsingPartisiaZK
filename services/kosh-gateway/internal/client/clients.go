// Package client holds gRPC client connections to all downstream services.
package client

import (
	"fmt"

	bb_pb "github.com/kosh/gateway/pb/bb"
	party_pb "github.com/kosh/gateway/pb/party"
	policy_pb "github.com/kosh/gateway/pb/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Clients struct {
	Coord  bb_pb.BulletinBoardClient
	Policy policy_pb.PolicyServiceClient
	// One PartyServiceClient per party (index 0 = party 1)
	Parties []party_pb.PartyServiceClient
}

func Dial(coordAddr, policyAddr string, partyAddrs []string) (*Clients, error) {
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	coordConn, err := grpc.NewClient(coordAddr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("coord dial: %w", err)
	}

	polConn, err := grpc.NewClient(policyAddr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("policy dial: %w", err)
	}

	parties := make([]party_pb.PartyServiceClient, 0, len(partyAddrs))
	for _, addr := range partyAddrs {
		conn, err := grpc.NewClient(addr, dialOpts...)
		if err != nil {
			return nil, fmt.Errorf("party dial %s: %w", addr, err)
		}
		parties = append(parties, party_pb.NewPartyServiceClient(conn))
	}

	return &Clients{
		Coord:   bb_pb.NewBulletinBoardClient(coordConn),
		Policy:  policy_pb.NewPolicyServiceClient(polConn),
		Parties: parties,
	}, nil
}
