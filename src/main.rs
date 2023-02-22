mod bitcoin_protocol;

use anyhow::Result;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::bitcoin_protocol::protocol::{verack_frame, version_frame, Codec, InternalFrame};

/// Simple program to establish a handshake with Bitcoin node
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP of Bitcoin node to connect
    #[arg(short, long)]
    ip: Ipv4Addr,

    /// Port of Bitcoin node to connect
    #[arg(short, long)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let ip_v4: Ipv4Addr = args.ip;
    let port = args.port;
    let mut framed_btc = Framed::new(
        TcpStream::connect(SocketAddr::new(IpAddr::V4(ip_v4), port)).await?,
        Codec::default(),
    );

    framed_btc
        .send(version_frame(
            ip_v4.to_ipv6_mapped(),
            port,
            "/Satoshi:0.18.0/".to_string(),
        ))
        .await?;
    println!("Version message sent");

    loop {
        if let Some(frame) = framed_btc.next().await {
            match frame {
                Ok(frame) => match frame.internal_frame {
                    InternalFrame::Version(_version) => framed_btc.send(verack_frame()).await?,
                    InternalFrame::VerAck(_) => {
                        println!("Handshake complete. Closing connection");
                        break;
                    }
                },
                Err(err) => println!("Got an error: {err}"),
            }
        }
    }

    Ok(())
}
