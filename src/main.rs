mod protocol;
mod consts;
mod http;
mod dh;
mod client;
mod conn;
mod codec;
mod handshake;

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

    let _framed_connn = handshake::handshake(stream).await?;

    Ok(())
}
