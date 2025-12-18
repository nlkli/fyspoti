fn main() {
    protobuf_codegen::Codegen::new()
        .out_dir("src/protocol")
        .inputs(&[
            "proto/keyexchange.proto",
            "proto/authentication.proto",
            "proto/mercury.proto",
        ])
        .include("proto")
        .run()
        .expect("protoc failed");
}
