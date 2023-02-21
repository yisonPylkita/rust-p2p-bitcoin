mod protocol;

use futures_util::{SinkExt, StreamExt};
use protocol::Codec;
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::protocol::{verack_frame, version_frame, InternalFrame};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let ip_v4: Ipv4Addr = args[1].parse().unwrap();
    let port = 8333 as u16;
    let stream = TcpStream::connect(SocketAddr::new(IpAddr::V4(ip_v4), port))
        .await
        .unwrap();
    let mut framed_btc = Framed::new(stream, Codec::default());

    let version_frame_raw =
        version_frame(ip_v4.to_ipv6_mapped(), port, "/Satoshi:0.18.0/".to_string());
    framed_btc.send(version_frame_raw).await.unwrap();
    println!("Version message sent");

    loop {
        match framed_btc.next().await {
            Some(Ok(frame)) => match frame.internal_frame {
                InternalFrame::Version(_version) => framed_btc.send(verack_frame()).await.unwrap(),
                InternalFrame::VerAck(_ack) => {
                    println!("Handshake complete. Closing connection");
                    break;
                }
            },
            Some(Err(err)) => {
                println!("Got an error: {err}");
            }
            None => {}
        }
    }

    Ok(())
}
