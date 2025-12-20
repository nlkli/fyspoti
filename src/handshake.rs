use hmac::{Hmac, Mac};
use protobuf::Message;
use rand::RngCore;
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use sha1::{Digest, Sha1};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Framed};
use thiserror::Error;

use crate::consts::SPOTIFY_VERSION;
use crate::codec::ApCodec;
use crate::dh::DhLocalKeys;

use crate::protocol;
use crate::protocol::keyexchange::{
    APResponseMessage, ClientHello, ClientResponsePlaintext, Platform, ProductFlags,
};

const SERVER_KEY: [u8; 256] = [
    0xac, 0xe0, 0x46, 0x0b, 0xff, 0xc2, 0x30, 0xaf, 0xf4, 0x6b, 0xfe, 0xc3, 0xbf, 0xbf, 0x86, 0x3d,
    0xa1, 0x91, 0xc6, 0xcc, 0x33, 0x6c, 0x93, 0xa1, 0x4f, 0xb3, 0xb0, 0x16, 0x12, 0xac, 0xac, 0x6a,
    0xf1, 0x80, 0xe7, 0xf6, 0x14, 0xd9, 0x42, 0x9d, 0xbe, 0x2e, 0x34, 0x66, 0x43, 0xe3, 0x62, 0xd2,
    0x32, 0x7a, 0x1a, 0x0d, 0x92, 0x3b, 0xae, 0xdd, 0x14, 0x02, 0xb1, 0x81, 0x55, 0x05, 0x61, 0x04,
    0xd5, 0x2c, 0x96, 0xa4, 0x4c, 0x1e, 0xcc, 0x02, 0x4a, 0xd4, 0xb2, 0x0c, 0x00, 0x1f, 0x17, 0xed,
    0xc2, 0x2f, 0xc4, 0x35, 0x21, 0xc8, 0xf0, 0xcb, 0xae, 0xd2, 0xad, 0xd7, 0x2b, 0x0f, 0x9d, 0xb3,
    0xc5, 0x32, 0x1a, 0x2a, 0xfe, 0x59, 0xf3, 0x5a, 0x0d, 0xac, 0x68, 0xf1, 0xfa, 0x62, 0x1e, 0xfb,
    0x2c, 0x8d, 0x0c, 0xb7, 0x39, 0x2d, 0x92, 0x47, 0xe3, 0xd7, 0x35, 0x1a, 0x6d, 0xbd, 0x24, 0xc2,
    0xae, 0x25, 0x5b, 0x88, 0xff, 0xab, 0x73, 0x29, 0x8a, 0x0b, 0xcc, 0xcd, 0x0c, 0x58, 0x67, 0x31,
    0x89, 0xe8, 0xbd, 0x34, 0x80, 0x78, 0x4a, 0x5f, 0xc9, 0x6b, 0x89, 0x9d, 0x95, 0x6b, 0xfc, 0x86,
    0xd7, 0x4f, 0x33, 0xa6, 0x78, 0x17, 0x96, 0xc9, 0xc3, 0x2d, 0x0d, 0x32, 0xa5, 0xab, 0xcd, 0x05,
    0x27, 0xe2, 0xf7, 0x10, 0xa3, 0x96, 0x13, 0xc4, 0x2f, 0x99, 0xc0, 0x27, 0xbf, 0xed, 0x04, 0x9c,
    0x3c, 0x27, 0x58, 0x04, 0xb6, 0xb2, 0x19, 0xf9, 0xc1, 0x2f, 0x02, 0xe9, 0x48, 0x63, 0xec, 0xa1,
    0xb6, 0x42, 0xa0, 0x9d, 0x48, 0x25, 0xf8, 0xb3, 0x9d, 0xd0, 0xe8, 0x6a, 0xf9, 0x48, 0x4d, 0xa1,
    0xc2, 0xba, 0x86, 0x30, 0x42, 0xea, 0x9d, 0xb3, 0x08, 0x6c, 0x19, 0x0e, 0x48, 0xb3, 0x9d, 0x66,
    0xeb, 0x00, 0x06, 0xa2, 0x5a, 0xee, 0xa1, 0x1b, 0x13, 0x87, 0x3c, 0xd7, 0x19, 0xe6, 0x55, 0xbd,
];

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("invalid key length")]
    InvalidLength,
    #[error("server key verification failed")]
    VerificationFailed,
}

pub async fn handshake<T: AsyncRead + AsyncWrite + Unpin>(mut conn: T) -> io::Result<Framed<T, ApCodec>> {
    let local_keys = DhLocalKeys::random(&mut rand::rng());
    let public_key = local_keys.public_key();

    let mut accumulator = client_hello(public_key, &mut conn).await?;
    conn.write_all(&accumulator).await?;

    let message: APResponseMessage = recv_packet(&mut conn, &mut accumulator).await?;

    let remote_key = message
        .challenge
        .get_or_default()
        .login_crypto_challenge
        .get_or_default()
        .diffie_hellman
        .get_or_default()
        .gs()
        .to_owned();
    let remote_signature = message
        .challenge
        .get_or_default()
        .login_crypto_challenge
        .get_or_default()
        .diffie_hellman
        .get_or_default()
        .gs_signature()
        .to_owned();

    let n = BigUint::from_bytes_be(&SERVER_KEY);
    let e = BigUint::new(vec![65537]);
    let public_key = RsaPublicKey::new(n, e)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, HandshakeError::VerificationFailed))?;

    let hash = Sha1::digest(&remote_key);
    let padding = Pkcs1v15Sign::new::<Sha1>();
    public_key
        .verify(padding, &hash, &remote_signature)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, HandshakeError::VerificationFailed))?;

    let shared_secret = local_keys.shared_secret(&remote_key);
    let (challenge, send_key, recv_key) = compute_keys(&shared_secret, &accumulator)?;
    let codec = ApCodec::new(&send_key, &recv_key);

    client_response(&mut conn, challenge).await?;

    Ok(codec.framed(conn))
}

async fn client_hello<T: AsyncWrite + Unpin>(public_key: Vec<u8>, conn: &mut T) -> io::Result<Vec<u8>> {
    let mut packet = ClientHello::new();
    packet
        .build_info
        .mut_or_insert_default()
        .set_product(protocol::keyexchange::Product::PRODUCT_CLIENT);
    packet
        .build_info
        .mut_or_insert_default()
        .product_flags
        .push(ProductFlags::PRODUCT_FLAG_NONE.into());
    packet
        .build_info
        .mut_or_insert_default()
        .set_platform(Platform::PLATFORM_LINUX_X86_64);
    packet
        .build_info
        .mut_or_insert_default()
        .set_version(SPOTIFY_VERSION);
    packet
        .cryptosuites_supported
        .push(protocol::keyexchange::Cryptosuite::CRYPTO_SUITE_SHANNON.into());
    packet
        .login_crypto_hello
        .mut_or_insert_default()
        .diffie_hellman
        .mut_or_insert_default()
        .set_gc(public_key);
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

    let payload_size = packet.compute_size();
    let size = 2 + 4 + payload_size as u32;

    let mut buf = Vec::with_capacity(2 + 4 + 4 + payload_size as usize);

    buf.push(0);
    buf.push(4);
    buf.extend_from_slice(&size.to_be_bytes());

    packet.write_to_vec(&mut buf)?;
    conn.write_all(&buf).await?;

    Ok(buf)
}

async fn client_response<T: AsyncWrite + Unpin>(conn: &mut T, challenge: Vec<u8>) -> io::Result<()> {
    let mut packet = ClientResponsePlaintext::new();
    packet
        .login_crypto_response
        .mut_or_insert_default()
        .diffie_hellman
        .mut_or_insert_default()
        .set_hmac(challenge);

    packet.pow_response.mut_or_insert_default();
    packet.crypto_response.mut_or_insert_default();

    let size = 4 + packet.compute_size();
    let mut buff = Vec::with_capacity(size as usize);
    buff.extend_from_slice(&(size as u32).to_be_bytes());
    packet.write_to_vec(&mut buff)?;

    conn.write_all(&buff).await?;
    Ok(())
}

async fn recv_packet<T, M>(conn: &mut T, acc: &mut Vec<u8>) -> io::Result<M>
where
    T: AsyncRead + Unpin,
    M: Message,
{
    let header = read_into_accumulator(conn, 4, acc).await?;
    let size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let data = read_into_accumulator(conn, size - 4, acc).await?;
    let message = M::parse_from_bytes(data)?;
    Ok(message)
}

async fn read_into_accumulator<'b, T: AsyncRead + Unpin>(
    conn: &mut T,
    size: usize,
    acc: &'b mut Vec<u8>,
) -> io::Result<&'b mut [u8]> {
    let offset = acc.len();
    acc.resize(offset + size, 0);

    conn.read_exact(&mut acc[offset..]).await?;
    Ok(&mut acc[offset..])
}

fn compute_keys(shared_secret: &[u8], packets: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    type HmacSha1 = Hmac<Sha1>;

    let mut data = Vec::with_capacity(0x64);
    for i in 1..6 {
        let mut mac = HmacSha1::new_from_slice(shared_secret)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, HandshakeError::InvalidLength))?;
        mac.update(packets);
        mac.update(&[i]);
        data.extend_from_slice(&mac.finalize().into_bytes());
    }

    let mut mac = HmacSha1::new_from_slice(&data[..0x14])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, HandshakeError::InvalidLength))?;
    mac.update(packets);

    Ok((
        mac.finalize().into_bytes().to_vec(),
        data[0x14..0x34].to_vec(),
        data[0x34..0x54].to_vec(),
    ))
}
