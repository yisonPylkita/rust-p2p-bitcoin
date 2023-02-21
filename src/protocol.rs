// https://en.bitcoin.it/wiki/Protocol_documentation
use bitcoin::hashes::sha256d;
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;
use bytes::BytesMut;
use rand::Rng;
use std::net::Ipv6Addr;
use std::{convert::TryInto, time::SystemTime};
use tokio_util::codec::{Decoder, Encoder};

#[derive(PartialEq, Debug)]
pub struct BaseFrame {
    pub magic: u32,
    pub command: String,
    pub internal_frame: InternalFrame,
}

#[derive(PartialEq, Debug)]
pub enum InternalFrame {
    Version(VersionFrame),
    VerAck(VerAckFrame),
}

#[derive(PartialEq, Debug)]
pub struct VersionFrame {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64, // TODO: Consider converting to a proper structure
    pub addr_recv: NetAddr,
    pub addr_from: NetAddr, // TODO: Remove. From docs - Field can be ignored. This used to be the network address of the node emitting this message, but most P2P implementations send 26 dummy bytes. The "services" field of the address would also be redundant with the second field of the version message.
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

#[derive(PartialEq, Debug)]
pub struct NetAddr {
    pub services: u64,
    pub ip: Ipv6Addr,
    pub port: u16,
}

impl NetAddr {
    fn new(ip: Ipv6Addr, port: u16) -> NetAddr {
        NetAddr {
            services: 0,
            ip,
            port,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut dst = Vec::with_capacity(26);
        dst.extend_from_slice(&self.services.to_le_bytes());
        dst.extend_from_slice(&self.ip.octets()[..]);
        dst.extend_from_slice(&self.port.to_be_bytes());

        dst
    }

    fn decode(src: &[u8; 26]) -> Result<NetAddr, std::io::Error> {
        let services = u64::from_le_bytes(src[0..8].try_into().unwrap());
        let ip_v6 = Ipv6Addr::from(<&[u8] as TryInto<[u8; 16]>>::try_into(&src[8..24]).unwrap());
        let port = u16::from_be_bytes(src[24..26].try_into().unwrap());

        Ok(NetAddr {
            services,
            ip: ip_v6,
            port,
        })
    }
}

impl VersionFrame {
    fn encode(&self) -> Vec<u8> {
        let mut dst = Vec::with_capacity(26);
        dst.extend_from_slice(&self.version.to_le_bytes());
        dst.extend_from_slice(&self.services.to_le_bytes());
        dst.extend_from_slice(&self.timestamp.to_le_bytes());
        dst.extend_from_slice(&self.addr_recv.encode());
        dst.extend_from_slice(&self.addr_from.encode());
        dst.extend_from_slice(&self.nonce.to_le_bytes());
        let user_agent_len = self.user_agent.len() as u8;
        dst.extend_from_slice(&user_agent_len.to_le_bytes());
        dst.extend_from_slice(&self.user_agent.as_bytes());
        dst.extend_from_slice(&self.start_height.to_le_bytes());
        dst.push(if self.relay { 0x01 } else { 0x00 });

        dst
    }

    fn decode(src: &mut BytesMut) -> Result<VersionFrame, std::io::Error> {
        let struct_min_size = 85;
        if src.len() < struct_min_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid size. Got size: {}", src.len()),
            ));
        }
        let version = i32::from_le_bytes(src[0..4].try_into().unwrap());
        let services = u64::from_le_bytes(src[4..12].try_into().unwrap());
        let timestamp = i64::from_le_bytes(src[12..20].try_into().unwrap());
        let addr_recv = NetAddr::decode(src[20..46].try_into().unwrap()).unwrap();
        let addr_from = NetAddr::decode(src[46..72].try_into().unwrap()).unwrap();
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
        let relay = u8::from_le_bytes(
            src[85 + user_agent_size..85 + user_agent_size + 1]
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
pub struct VerAckFrame {}

impl VerAckFrame {
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    fn decode(src: &mut BytesMut) -> Result<VerAckFrame, std::io::Error> {
        if src.len() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid size"),
            ));
        }

        Ok(VerAckFrame {})
    }
}

#[derive(Default)]
pub struct Codec {}

impl Encoder<BaseFrame> for Codec {
    type Error = std::io::Error;

    fn encode(&mut self, item: BaseFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item.magic.to_le_bytes());
        dst.extend_from_slice(&str_to_padded_bytes(&item.command));
        let payload_bytes = match item.internal_frame {
            InternalFrame::Version(frame) => frame.encode(),
            InternalFrame::VerAck(frame) => frame.encode(),
        };
        let payload_size = payload_bytes.len() as u32;
        dst.extend_from_slice(&payload_size.to_le_bytes());
        let checksum = calculate_checksum(&payload_bytes[..]);
        dst.extend_from_slice(&checksum);
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
            src.reserve(MIN_LENGTH - src.len());
            return Ok(None);
        }
        let magic = u32::from_le_bytes(src[0..4].try_into().unwrap());
        let length = u32::from_le_bytes(src[16..20].try_into().unwrap());
        if src.len() < length as usize {
            src.reserve(MIN_LENGTH + length as usize - src.len());
            return Ok(None);
        }
        let src = src.split_to(MIN_LENGTH + length as usize);
        let command = bytes_to_str(&src[4..16]);

        if (MIN_LENGTH + length as usize) < src.len() {
            return Ok(None);
        }
        let checksum = &src[20..24];
        let internal_payload = &src[24..24 + length as usize];
        if calculate_checksum(internal_payload) != checksum {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid checksum"),
            ));
        }
        println!("Received command: {command}");
        let internal_frame = match command {
            "version" => InternalFrame::Version(
                VersionFrame::decode(&mut BytesMut::from(internal_payload)).unwrap(),
            ),

            "verack" => InternalFrame::VerAck(
                VerAckFrame::decode(&mut BytesMut::from(internal_payload)).unwrap(),
            ),

            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Command not supported"),
                ))
            }
        };

        Ok(Some(BaseFrame {
            magic,
            command: command.to_string(),
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
    let mut result = vec![0x00; 12];
    for idx in 0..data.len() {
        result[idx] = data.as_bytes()[idx];
    }

    result
}

fn calculate_checksum(data: &[u8]) -> [u8; 4] {
    let mut reader: &[u8] = data;
    let mut engine = sha256::HashEngine::default();
    std::io::copy(&mut reader, &mut engine).unwrap();
    let hash = sha256d::Hash::from_engine(engine);

    [hash[0], hash[1], hash[2], hash[3]]
}

pub fn version_frame(ip: Ipv6Addr, port: u16, user_agent: String) -> BaseFrame {
    BaseFrame {
        magic: 0xd9b4bef9,
        command: "version".to_string(),
        internal_frame: InternalFrame::Version(VersionFrame {
            version: 70001,
            services: 0,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            addr_recv: NetAddr::new(ip, port),
            addr_from: NetAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0),
            nonce: rand::thread_rng().gen::<u64>(),
            user_agent,
            start_height: 0,
            relay: false,
        }),
    }
}

pub fn verack_frame() -> BaseFrame {
    BaseFrame {
        magic: 0xd9b4bef9,
        command: "verack".to_string(),
        internal_frame: InternalFrame::VerAck(VerAckFrame {}),
    }
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
                0x69, 0x3a, 0x30, 0x2e, 0x37, 0x2e, 0x32, 0x2f, 0xc0, 0x3e, 0x03, 0x00, 0x00,
            ][..],
        );
        let mut codec = Codec {};
        let result = codec.decode(&mut raw_frame).unwrap().unwrap();
        assert_eq!(
            result,
            BaseFrame {
                magic: 0xd9b4bef9,
                command: "version".to_string(),
                internal_frame: InternalFrame::Version(VersionFrame {
                    version: 60002,
                    services: 1,
                    timestamp: 1355854353,
                    addr_recv: NetAddr {
                        services: 1,
                        ip: "::ffff:0.0.0.0".parse().unwrap(),
                        port: 0
                    },
                    addr_from: NetAddr {
                        services: 0,
                        ip: "::ffff:0.0.0.0".parse().unwrap(),
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
                internal_frame: InternalFrame::VerAck(VerAckFrame {})
            }
        );
    }

    #[test]
    fn encode_version_frame() {
        let mut codec = Codec {};
        let mut encoded_frame = BytesMut::new();
        codec
            .encode(
                BaseFrame {
                    magic: 0xd9b4bef9,
                    command: "version".to_string(),
                    internal_frame: InternalFrame::Version(VersionFrame {
                        version: 60002,
                        services: 1,
                        timestamp: 1355854353,
                        addr_recv: NetAddr {
                            services: 1,
                            ip: "::ffff:0.0.0.0".parse().unwrap(),
                            port: 0,
                        },
                        addr_from: NetAddr {
                            services: 0,
                            ip: "::ffff:0.0.0.0".parse().unwrap(),
                            port: 0,
                        },
                        nonce: 7284544412836900411,
                        user_agent: "/Satoshi:0.7.2/".to_string(),
                        start_height: 212672,
                        relay: false,
                    }),
                },
                &mut encoded_frame,
            )
            .unwrap();
        let expected_frame = BytesMut::from(
            &[
                0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x35, 0x8d, 0x49, 0x32, 0x62, 0xea, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0xb2, 0xd0, 0x50, 0x00, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x2e,
                0xb3, 0x5d, 0x8c, 0xe6, 0x17, 0x65, 0x0f, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
                0x69, 0x3a, 0x30, 0x2e, 0x37, 0x2e, 0x32, 0x2f, 0xc0, 0x3e, 0x03, 0x00, 0x00,
            ][..],
        );
        assert_eq!(hex::encode(expected_frame), hex::encode(encoded_frame));
    }

    #[test]
    fn encode_verack_frame() {
        let mut codec = Codec {};
        let mut encoded_frame = BytesMut::new();
        codec
            .encode(
                BaseFrame {
                    magic: 0xd9b4bef9,
                    command: "verack".to_string(),
                    internal_frame: InternalFrame::VerAck(VerAckFrame {}),
                },
                &mut encoded_frame,
            )
            .unwrap();
        let expected_frame = BytesMut::from(
            &[
                0xF9, 0xBE, 0xB4, 0xD9, 0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xF6, 0xE0, 0xE2,
            ][..],
        );
        assert_eq!(hex::encode(expected_frame), hex::encode(encoded_frame));
    }
}
