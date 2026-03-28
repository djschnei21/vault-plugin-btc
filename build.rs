fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "proto/vault/backend.proto",
                "proto/plugin/grpc_broker.proto",
                "proto/plugin/grpc_controller.proto",
                "proto/plugin/grpc_stdio.proto",
            ],
            &["proto/"],
        )?;
    Ok(())
}
