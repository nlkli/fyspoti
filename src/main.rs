use protobuf::Message;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
mod protocol;
mod consts;
mod http;
mod dh;
mod client;
mod conn;
mod codec;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = http::reqwest_ap_resolve_data().await?;
    if data.accesspoint.is_empty() {
        panic!("empty accesspoint list");
    }
    println!("{:#?}", data);
    let accesspoint = data
        .accesspoint_4070()
        .next()
        .unwrap();

    let (host, port) = accesspoint
        .split_once(":")
        .map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(4070)))
        .unwrap();

    let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let (mut reader, mut writer) = stream.into_split();

    let local_keys = dh::DhLocalKeys::random(&mut rand::rng());
    let gc = local_keys.public_key();

    println!("gc len: {}", gc.len());
    println!("gc: {:?}", gc);

    let mut packet = protocol::keyexchange::ClientHello::new();
    packet
        .build_info
        .mut_or_insert_default()
        .set_product(protocol::keyexchange::Product::PRODUCT_CLIENT);
    packet
        .build_info
        .mut_or_insert_default()
        .product_flags
        .push(protocol::keyexchange::ProductFlags::PRODUCT_FLAG_NONE.into());
    packet
        .build_info
        .mut_or_insert_default()
        .set_platform(protocol::keyexchange::Platform::PLATFORM_LINUX_X86_64);
    packet
        .build_info
        .mut_or_insert_default()
        .set_version(124200290);
    packet
        .cryptosuites_supported
        .push(protocol::keyexchange::Cryptosuite::CRYPTO_SUITE_SHANNON.into());
    packet
        .login_crypto_hello
        .mut_or_insert_default()
        .diffie_hellman
        .mut_or_insert_default()
        .set_gc(gc);
    packet
        .login_crypto_hello
        .mut_or_insert_default()
        .diffie_hellman
        .mut_or_insert_default()
        .set_server_keys_known(1);

    let mut client_nonce = vec![0; 0x10];
    rand::rng().fill_bytes(&mut client_nonce);

    packet.set_client_nonce(client_nonce);
    packet.set_padding(vec![0x1e]);

    let size = 2 + 4 + packet.compute_size() as u32;
    let mut buff = vec![0, 4];
    buff.extend_from_slice(&size.to_be_bytes());
    packet.write_to_vec(&mut buff)?;

    println!("Packet length: {}", buff.len());

    writer.write_all(&buff).await?;
    println!("ClientHello sent");

    tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await.unwrap();
        let total_len = u32::from_be_bytes(len_buf) as usize;

        let mut payload = vec![0u8; total_len - 4];
        reader.read_exact(&mut payload).await.unwrap();
        let message = protocol::keyexchange::APResponseMessage::parse_from_bytes(&payload).unwrap();
        println!("Server response: {:#?}", message);
    });

    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    Ok(())
}
