mod protocol;
mod consts;
mod http;
mod dh;
mod client;
mod codec;
mod handshake;
// use futures_util::{SinkExt, StreamExt};
// use protobuf::Message;

// use crate::protocol::authentication::{APWelcome, ClientResponseEncrypted, CpuFamily, Os};

async fn conn() -> Result<(), Box<dyn std::error::Error>> {
    let data = http::reqwest_ap_resolve_data().await?;
    if data.accesspoint.is_empty() {
        panic!("empty accesspoint list");
    }

    println!("{:#?}", data);

    let (host, port) = data
        .accesspoint_4070()
        .next()
        .unwrap();

    let stream = tokio::net::TcpStream::connect((host, port)).await?;
    let transport = handshake::handshake(stream).await?;

    // let device_id = uuid::Uuid::new_v4().as_hyphenated().to_string();

    // let mut packet = ClientResponseEncrypted::new();
    // if let Some(username) = credentials.username {
    //     packet
    //         .login_credentials
    //         .mut_or_insert_default()
    //         .set_username(username);
    // }
    // packet
    //     .login_credentials
    //     .mut_or_insert_default()
    //     .set_typ(credentials.auth_type);
    // packet
    //     .login_credentials
    //     .mut_or_insert_default()
    //     .set_auth_data(credentials.auth_data);
    // packet
    //     .system_info
    //     .mut_or_insert_default()
    //     .set_cpu_family(CpuFamily::CPU_X86_64);
    // packet.system_info.mut_or_insert_default().set_os(Os::OS_LINUX);
    // // packet
    // //     .system_info
    // //     .mut_or_insert_default()
    // //     .set_system_information_string("".into());
    // packet
    //     .system_info
    //     .mut_or_insert_default()
    //     .set_device_id(device_id);
    // // packet.set_version_string("".into());

    // let cmd = consts::PacketType::Login;
    // let data = packet.write_to_bytes()?;

    // transport.send((cmd as u8, data)).await?;

    // let (cmd, data) = transport
    //     .next()
    //     .await
    //     .ok_or("auth error")??;
    // let packet_type = consts::PacketType::from(cmd);
    // let result = match packet_type {
    //     consts::PacketType::APWelcome => {
    //         let welcome_data = APWelcome::parse_from_bytes(data.as_ref())?;

    //         let reusable_credentials = Credentials {
    //             username: Some(welcome_data.canonical_username().to_owned()),
    //             auth_type: welcome_data.reusable_auth_credentials_type(),
    //             auth_data: welcome_data.reusable_auth_credentials().to_owned(),
    //         };

    //         Ok(reusable_credentials)
    //     }
    //     consts::PacketType::AuthFailure => {
    //         let error_data = APLoginFailed::parse_from_bytes(data.as_ref())?;
    //         Err(error_data.into())
    //     }
    //     _ => {
    //         // trace!("Did not expect {cmd:?} AES key packet with data {data:#?}");
    //         Err(AuthenticationError::Packet(cmd))
    //     }
    // };

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    conn().await?;

    Ok(())
}
