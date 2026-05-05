fn main() {
    tonic_build::configure()
        .build_server(true)
        .compile(
            &[
                "../proto/party.proto",
                "../proto/bulletin_board.proto",
                "../proto/keystore.proto",
                "../proto/pqc.proto",
                "../proto/chain_relay.proto",
            ],
            &["../proto"],
        )
        .unwrap();
}
