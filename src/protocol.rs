// https://en.bitcoin.it/wiki/Protocol_documentation

use bytes::BytesMut;
use std::convert::TryInto;
use tokio_util::codec::{Decoder, Encoder};

#[derive(PartialEq, Debug)]
struct BaseFrame {
    magic: u32,
    command: String,
    length: u32,
    checksum: u32,
    internal_frame: InternalFrame,
}

#[derive(PartialEq, Debug)]
enum InternalFrame {
    Version(VersionFrame),
    VerAck(VerAckFrame),
}

#[derive(PartialEq, Debug)]
struct VersionFrame {
    version: i32,
    services: u64,
    timestamp: i64, // TODO: Consider converting to a proper structure
    addr_recv: NetAddrVersion,
    addr_from: NetAddrVersion,
    nonce: u64,
    user_agent: String,
    start_height: i32,
    relay: bool,
}

#[derive(PartialEq, Debug)]
struct NetAddrVersion {
    services: u64,
    ip_v6_v4: [u8; 16],
    port: u16,
}

impl NetAddrVersion {
    fn encode(&self) -> Vec<u8> {
        unimplemented!();
    }

    fn decode(src: &[u8; 26]) -> Result<NetAddrVersion, std::io::Error> {
        let services = u64::from_le_bytes(src[0..8].try_into().unwrap());
        let ip_v6_v4: [u8; 16] = src[8..24].try_into().unwrap();
        let port = u16::from_le_bytes(src[24..26].try_into().unwrap());

        Ok(NetAddrVersion {
            services,
            ip_v6_v4,
            port,
        })
    }
}

impl VersionFrame {
    fn encode(&self) -> Vec<u8> {
        unimplemented!();
    }

    fn decode(src: &mut BytesMut) -> Result<VersionFrame, std::io::Error> {
        let struct_min_size = 85;
        if src.len() < struct_min_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid size"),
            ));
        }
        let version = i32::from_le_bytes(src[0..4].try_into().unwrap());
        let services = u64::from_le_bytes(src[4..12].try_into().unwrap());
        let timestamp = i64::from_le_bytes(src[12..20].try_into().unwrap());
        let addr_recv = NetAddrVersion::decode(src[20..46].try_into().unwrap()).unwrap();
        // TODO: All below only in version ≥ 106
        let addr_from = NetAddrVersion::decode(src[46..72].try_into().unwrap()).unwrap();
        let nonce = u64::from_le_bytes(src[72..80].try_into().unwrap());
        let user_agent_size = u8::from_le_bytes(src[80..81].try_into().unwrap()) as usize;
        let user_agent = if user_agent_size == 0x00 {
            String::new()
        } else {
            String::from_utf8(src[81..81 + user_agent_size].to_vec()).unwrap()
        };
        let start_height = i32::from_le_bytes(
            src[81 + user_agent_size..81 + user_agent_size + 4]
                .try_into()
                .unwrap(),
        );
        // TODO: relay only in version ≥ 70001
        let relay = u8::from_le_bytes(
            src[83 + user_agent_size..83 + user_agent_size + 1]
                .try_into()
                .unwrap(),
        ) == 0x00;

        Ok(VersionFrame {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }
}

#[derive(PartialEq, Debug)]
struct VerAckFrame {}

impl VerAckFrame {
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn decode(src: &mut BytesMut) -> Result<VerAckFrame, std::io::Error> {
        // TODO: ensure src.len() == 0
        Ok(VerAckFrame {})
    }
}

struct Codec {}

impl Encoder<BaseFrame> for Codec {
    type Error = std::io::Error;

    fn encode(&mut self, item: BaseFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item.magic.to_le_bytes());
        dst.extend_from_slice(&str_to_padded_bytes(&item.command));
        let payload_bytes = match item.internal_frame {
            InternalFrame::Version(frame) => frame.encode(),
            InternalFrame::VerAck(frame) => frame.encode(),
        };
        dst.extend_from_slice(&payload_bytes.len().to_le_bytes());
        let checksum: u32 = 0x00; // TODO: implement checksum calculation
        dst.extend_from_slice(&checksum.to_le_bytes());
        dst.extend_from_slice(&payload_bytes);

        Ok(())
    }
}

impl Decoder for Codec {
    type Item = BaseFrame;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        const MIN_LENGTH: usize = 24;
        if src.len() < MIN_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid size"),
            ));
        }
        let magic = u32::from_le_bytes(src[0..4].try_into().unwrap());
        let command = bytes_to_str(&src[4..16]);

        let length = u32::from_le_bytes(src[16..20].try_into().unwrap());
        if MIN_LENGTH + length as usize != src.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid size"),
            ));
        }
        let checksum = u32::from_le_bytes(src[20..24].try_into().unwrap());
        let internal_payload = &src[24..24 + length as usize];
        println!("Command: {command}");
        let internal_frame = match command {
            "version" => InternalFrame::Version(
                VersionFrame::decode(&mut BytesMut::from(internal_payload)).unwrap(),
            ),
            "verack" => InternalFrame::VerAck(
                VerAckFrame::decode(&mut BytesMut::from(internal_payload)).unwrap(),
            ),
            _ => unimplemented!(),
        };

        Ok(Some(BaseFrame {
            magic,
            command: command.to_string(),
            length,
            checksum,
            internal_frame,
        }))
    }
}

fn bytes_to_str(data: &[u8]) -> &str {
    let idx = data.iter().position(|ch| ch == &0x00).unwrap();
    std::str::from_utf8(&data[..idx]).unwrap()
}

fn str_to_padded_bytes(data: &str) -> Vec<u8> {
    if data.len() >= 12 {
        panic!("Buffer too large");
    }
    let mut result: [u8; 12] = [0; 12];
    for idx in 0..11 {
        result[idx] = data.as_bytes()[idx];
    }

    Vec::from(result)
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn decode_version_frame() {
        let mut raw_frame = BytesMut::from(
            &[
                0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x35, 0x8d, 0x49, 0x32, 0x62, 0xea, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0xb2, 0xd0, 0x50, 0x00, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x2e,
                0xb3, 0x5d, 0x8c, 0xe6, 0x17, 0x65, 0x0f, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
                0x69, 0x3a, 0x30, 0x2e, 0x37, 0x2e, 0x32, 0x2f, 0xc0, 0x3e, 0x03, 0x00,
            ][..],
        );
        let mut codec = Codec {};
        let result = codec.decode(&mut raw_frame).unwrap().unwrap();
        assert_eq!(
            result,
            BaseFrame {
                magic: 0xd9b4bef9,
                command: "version".to_string(),
                length: 100,
                checksum: 0x32498d35,
                internal_frame: InternalFrame::Version(VersionFrame {
                    version: 60002,
                    services: 1,
                    timestamp: 1355854353,
                    addr_recv: NetAddrVersion {
                        services: 1,
                        ip_v6_v4: vec![
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                            0x00, 0x00, 0x00, 0x00,
                        ]
                        .try_into()
                        .unwrap(),
                        port: 0
                    },
                    addr_from: NetAddrVersion {
                        services: 0,
                        ip_v6_v4: vec![
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                            0x00, 0x00, 0x00, 0x00,
                        ]
                        .try_into()
                        .unwrap(),
                        port: 0
                    },
                    nonce: 7284544412836900411,
                    user_agent: "/Satoshi:0.7.2/".to_string(),
                    start_height: 212672,
                    relay: false,
                })
            }
        );
    }

    #[test]
    fn decode_verack_frame() {
        let mut raw_frame = BytesMut::from(
            &[
                0xF9, 0xBE, 0xB4, 0xD9, 0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xF6, 0xE0, 0xE2,
            ][..],
        );
        let mut codec = Codec {};
        let result = codec.decode(&mut raw_frame).unwrap().unwrap();
        assert_eq!(
            result,
            BaseFrame {
                magic: 0xd9b4bef9,
                command: "verack".to_string(),
                length: 0,
                checksum: 0xe2e0f65d,
                internal_frame: InternalFrame::VerAck(VerAckFrame {})
            }
        );
    }
}
