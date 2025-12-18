use protobuf::Message;
use rand::RngCore;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
mod protocol;
use std::sync::LazyLock;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::{CryptoRng, Rng};

static DH_GENERATOR: LazyLock<BigUint> = LazyLock::new(|| BigUint::from_bytes_be(&[0x02]));
static DH_PRIME: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::from_bytes_be(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2,
        0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67,
        0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e,
        0x34, 0x04, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
        0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5,
        0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ])
});

fn powm(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let mut base = base.clone();
    let mut exp = exp.clone();
    let mut result: BigUint = One::one();

    while !exp.is_zero() {
        if exp.is_odd() {
            result = (result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }

    result
}

pub struct DhLocalKeys {
    private_key: BigUint,
    public_key: BigUint,
}

impl DhLocalKeys {
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> DhLocalKeys {
        let mut bytes = [0u8; 95];
        rng.fill_bytes(&mut bytes);
        let private_key = BigUint::from_bytes_le(&bytes);
        let public_key = powm(&DH_GENERATOR, &private_key, &DH_PRIME);

        DhLocalKeys {
            private_key,
            public_key,
        }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.to_bytes_be()
    }

    pub fn shared_secret(&self, remote_key: &[u8]) -> Vec<u8> {
        let shared_key = powm(
            &BigUint::from_bytes_be(remote_key),
            &self.private_key,
            &DH_PRIME,
        );
        shared_key.to_bytes_be()
    }
}

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

    let local_keys = DhLocalKeys::random(&mut rand::rng());
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
