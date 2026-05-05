/// Integration test for kosh-party gRPC service.
/// Tests: GetStatus, StartDkg streaming events.
/// Requires kosh-coordinator running (started by the test).

use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

pub mod party_pb {
    tonic::include_proto!("kosh.party");
}
pub mod bb_pb {
    tonic::include_proto!("kosh.bb");
}

use party_pb::{
    party_service_client::PartyServiceClient, DkgRequest, StatusRequest,
    dkg_event::Phase as DkgPhase,
};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn wait_ready(addr: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "service not ready at {addr}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn start_coordinator(port: u16) -> Guard {
    // Build and start kosh-coordinator
    let coord_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("kosh-coordinator");
    let bin_path = std::env::temp_dir().join(format!("kosh-coordinator-{port}"));

    let build = Command::new("go")
        .args(["build", "-o", bin_path.to_str().unwrap(), "./cmd/coordinator"])
        .current_dir(&coord_dir)
        .output()
        .expect("failed to build coordinator");
    assert!(build.status.success(), "coordinator build failed: {:?}", String::from_utf8_lossy(&build.stderr));

    let proc = Command::new(&bin_path)
        .env("PORT", port.to_string())
        .spawn()
        .expect("failed to start coordinator");
    wait_ready(&format!("127.0.0.1:{port}"), Duration::from_secs(10));
    Guard(proc)
}

fn start_party(port: u16, party_index: u32, coordinator_port: u16) -> Guard {
    let bin = env!("CARGO_BIN_EXE_kosh-party");
    let proc = Command::new(bin)
        .env("PORT", port.to_string())
        .env("PARTY_INDEX", party_index.to_string())
        .env("NUM_PARTIES", "3")
        .env("COORDINATOR_ADDR", format!("http://127.0.0.1:{coordinator_port}"))
        .env("KEYSTORE_ADDR", "http://127.0.0.1:50070")
        .env("PQC_ADDR", "http://127.0.0.1:50080")
        .env("CHAIN_RELAY_ADDR", "http://127.0.0.1:50053")
        .env("RUST_LOG", "info")
        .spawn()
        .expect("failed to start kosh-party");
    wait_ready(&format!("127.0.0.1:{port}"), Duration::from_secs(10));
    Guard(proc)
}

async fn party_client(port: u16) -> PartyServiceClient<tonic::transport::Channel> {
    PartyServiceClient::connect(format!("http://127.0.0.1:{port}"))
        .await
        .unwrap()
}

#[tokio::test]
async fn test_get_status() {
    let party_port = free_port();
    let coord_port = free_port();

    let _coord = start_coordinator(coord_port);
    let _party = start_party(party_port, 1, coord_port);

    let mut client = party_client(party_port).await;
    let resp = client.get_status(StatusRequest {}).await.unwrap().into_inner();

    assert_eq!(resp.party_index, 1);
    assert_eq!(resp.current_phase, "Idle");
    println!("GetStatus OK: party_index={}, phase={}", resp.party_index, resp.current_phase);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_3party_streams_all_phases() {
    let coord_port = free_port();
    let p1_port = free_port();
    let p2_port = free_port();
    let p3_port = free_port();

    let _coord = start_coordinator(coord_port);
    let _p1 = start_party(p1_port, 1, coord_port);
    let _p2 = start_party(p2_port, 2, coord_port);
    let _p3 = start_party(p3_port, 3, coord_port);

    // Start DKG on all 3 parties simultaneously
    let key_id = 99u32;

    let mut c1 = party_client(p1_port).await;
    let mut c2 = party_client(p2_port).await;
    let mut c3 = party_client(p3_port).await;

    let dkg_req = || DkgRequest { key_id, num_parties: 3, threshold: 2 };

    let (s1, s2, s3) = tokio::join!(
        c1.start_dkg(dkg_req()),
        c2.start_dkg(dkg_req()),
        c3.start_dkg(dkg_req()),
    );

    let mut stream1 = s1.unwrap().into_inner();
    let mut stream2 = s2.unwrap().into_inner();
    let mut stream3 = s3.unwrap().into_inner();

    // Drain events from all streams concurrently until DKG_COMPLETE or DKG_FAILED
    let collect = |mut stream: tonic::codec::Streaming<party_pb::DkgEvent>| async move {
        let mut events = Vec::new();
        while let Ok(Some(ev)) = stream.message().await {
            let phase = ev.phase;
            println!("  DKG event phase={phase}: {}", ev.message);
            events.push(ev);
            if phase == DkgPhase::DkgComplete as i32 || phase == DkgPhase::DkgFailed as i32 {
                break;
            }
        }
        events
    };

    let (e1, e2, e3) = tokio::join!(collect(stream1), collect(stream2), collect(stream3));

    // Each stream must end with DKG_COMPLETE
    let check = |events: Vec<party_pb::DkgEvent>, party: u32| {
        let last = events.last().expect("no DKG events received");
        assert_eq!(
            last.phase,
            DkgPhase::DkgComplete as i32,
            "party {party} DKG did not complete: last event = {:?}",
            last
        );
        println!("Party {party} DKG complete: {}", last.message);
    };
    check(e1, 1);
    check(e2, 2);
    check(e3, 3);
}
