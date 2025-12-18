use protobuf::Message;
use rand::RngCore;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
mod protocol;
mod consts;
mod dh;

#[derive(Debug, Copy, Clone)]
pub enum PacketType {
    SecretBlock = 0x02,
    Ping = 0x04,
    StreamChunk = 0x08,
    StreamChunkRes = 0x09,
    ChannelError = 0x0a,
    ChannelAbort = 0x0b,
    RequestKey = 0x0c,
    AesKey = 0x0d,
    AesKeyError = 0x0e,
    Image = 0x19,
    CountryCode = 0x1b,
    Pong = 0x49,
    PongAck = 0x4a,
    Pause = 0x4b,
    ProductInfo = 0x50,
    LegacyWelcome = 0x69,
    LicenseVersion = 0x76,
    Login = 0xab,
    APWelcome = 0xac,
    AuthFailure = 0xad,
    MercuryReq = 0xb2,
    MercurySub = 0xb3,
    MercuryUnsub = 0xb4,
    MercuryEvent = 0xb5,
    TrackEndedTime = 0x82,
    UnknownDataAllZeros = 0x1f,
    PreferredLocale = 0x74,
    Unknown0x0f = 0x0f,
    Unknown0x10 = 0x10,
    Unknown0x4f = 0x4f,
    Unknown0xb6 = 0xb6,
}

#[derive(Deserialize, Default, Debug)]
pub struct ApResolveData {
    accesspoint: Vec<String>,
    dealer: Vec<String>,
    spclient: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let response =
        reqwest::get("https://apresolve.spotify.com/?type=accesspoint&type=dealer&type=spclient")
            .await?;
    let body = response.bytes().await?;
    let data = serde_json::from_slice::<ApResolveData>(&body)?;

    if data.accesspoint.is_empty() {
        panic!("empty accesspoint list");
    }

    println!("{:#?}", data);

    let accesspoint = data
        .accesspoint
        .iter()
        .find(|s| s.ends_with(":4070"))
        .cloned()
        .unwrap();

    let (host, port) = accesspoint
        .split_once(":")
        .map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(443)))
        .unwrap();

    let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let (mut reader, mut writer) = stream.into_split();

    let local_keys = dh::DhLocalKeys::random(&mut rand::rng());
    let gc = local_keys.public_key();

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
