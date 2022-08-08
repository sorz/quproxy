mod crypto;
mod tls;

use std::{cmp, io};

use bytes::{Buf, Bytes, BytesMut};
use ring::{
    aead::{quic::HeaderProtectionKey, Aad, LessSafeKey},
    error::Unspecified,
};
use tracing::info;

use crate::app::types::RemoteAddr;

use self::crypto::InitialSecret;

pub(super) const MIN_DATAGRAM_SIZE_BYTES: usize = 1200;

#[derive(Debug)]
pub(super) struct QuicConnection {
    pub(super) remote_orig: RemoteAddr,
    pub(super) remote_name: Option<String>,
}

#[derive(Debug)]
pub(super) enum ParseError {
    NotValidQuicPacket,
    NotInitialPacket,
    NoEnoughData,
}

impl From<io::Error> for ParseError {
    fn from(_: io::Error) -> Self {
        Self::NoEnoughData
    }
}

impl From<Unspecified> for ParseError {
    fn from(_: Unspecified) -> Self {
        Self::NotValidQuicPacket
    }
}

impl QuicConnection {
    pub(super) fn try_from(remote: RemoteAddr, pkt: InitialPacket) -> Result<Self, ParseError> {
        let crypto_msg = pkt.crypto_message()?;
        let remote_name = if crypto_msg.is_empty() {
            None
        } else {
            tls::get_server_name_from_client_hello(crypto_msg)
        };
        Ok(Self {
            remote_orig: remote,
            remote_name,
        })
    }
}

pub(super) struct InitialPacket {
    payload: Bytes,
}

impl InitialPacket {
    pub(super) fn decode(pkt: Bytes) -> Result<Self, ParseError> {
        let mut buf = pkt.clone();
        if pkt.len() < MIN_DATAGRAM_SIZE_BYTES {
            return Err(ParseError::NoEnoughData);
        }
        let flags = buf[0];
        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        buf.advance(1 + 4);
        if version != 1 {
            return Err(ParseError::NotValidQuicPacket);
        }
        if flags & 0xf0 != 0xc0 {
            return Err(ParseError::NotInitialPacket);
        }

        // Decode unprotected header
        let dcid = decode_conn_id(&mut buf)?;
        let _scid = decode_conn_id(&mut buf)?;
        let token = {
            let len = decode_var_int(&mut buf) as usize;
            if len > buf.remaining() {
                return Err(ParseError::NoEnoughData);
            }
            buf.slice(0..len)
        };
        buf.advance(token.len());
        let payload_len = decode_var_int(&mut buf) as usize;
        if buf.remaining() < payload_len {
            return Err(ParseError::NoEnoughData);
        }
        let pn_offset = pkt.len() - buf.remaining();
        let mut pkt: BytesMut = pkt.slice(..pn_offset + payload_len).as_ref().into();

        // Decode protected header
        let init_secret = InitialSecret::new(&dcid);
        let header_key: HeaderProtectionKey = (&init_secret).into();
        let mask = {
            let len = header_key.algorithm().sample_len();
            if buf.remaining() < 4 + len {
                return Err(ParseError::NoEnoughData);
            }
            header_key.new_mask(&buf[4..4 + len]).unwrap()
        };
        drop(buf);
        pkt[0] ^= mask[0] & 0x0f;
        let pn_len = ((pkt[0] & 0x03) + 1) as usize;
        let pkt_no = {
            let mut n = 0u32;
            for i in 0..pn_len {
                pkt[pn_offset + i] ^= mask[1 + i];
                n = (n << 8) | pkt[pn_offset + i] as u32;
            }
            n
        };
        let header = pkt.split_to(pn_offset + pn_len).freeze();
        let mut payload = pkt;

        // Decode protected payload
        let key: LessSafeKey = (&init_secret).into();
        key.open_in_place(
            init_secret.nonce(pkt_no as u64),
            Aad::from(header),
            &mut payload,
        )?;
        payload.truncate(payload.len() - 16);
        Ok(Self {
            payload: payload.freeze(),
        })
    }

    fn crypto_message(&self) -> Result<Bytes, ParseError> {
        let mut buf = self.payload.clone();
        // Use `msg` for avoid copy, fallback to `msg_buf` if CRYPTO frames
        // are non-continous.
        let mut msg: Option<Bytes> = None;
        let mut msg_buf = BytesMut::new();
        let mut ranges = Vec::new();
        while buf.has_remaining() {
            let frame_type = buf[0];
            buf.advance(1);
            match frame_type {
                // PADDING | PING
                0x00 | 0x01 => (),
                // ACK, should not in client's initial packet
                0x02 | 0x03 => return Err(ParseError::NotInitialPacket),
                // CRYPTO
                0x06 => {
                    let pos = decode_var_int(&mut buf) as usize;
                    let len = decode_var_int(&mut buf) as usize;
                    if pos + len > self.payload.len() {
                        // Prevent allocate lots of memory
                        return Err(ParseError::NotValidQuicPacket);
                    }
                    if msg.is_none() && msg_buf.is_empty() && pos == 0 {
                        msg = Some(buf.slice(..len));
                    } else {
                        if let Some(m) = msg {
                            msg_buf.extend_from_slice(&m);
                            ranges.push(0..m.len());
                            msg = None;
                        }
                        if msg_buf.len() < pos + len {
                            msg_buf.resize(pos + len, 0);
                        }
                        msg_buf[pos..pos + len].copy_from_slice(&buf[..len]);
                        ranges.push(pos..pos + len);
                    }
                    buf.advance(len);
                }
                // Protocol violation
                _ => return Err(ParseError::NotValidQuicPacket),
            }
        }
        if let Some(msg) = msg {
            Ok(msg)
        } else {
            let mut len = 0;
            ranges.sort_by_key(|r| r.start);
            for range in ranges {
                if range.start <= len {
                    len = cmp::max(len, range.end);
                } else {
                    break;
                }
            }
            if len < msg_buf.len() {
                info!("Gap in CRYPTO frames ({}/{})", len, msg_buf.len());
                msg_buf.truncate(len);
            }
            Ok(msg_buf.freeze())
        }
    }
}

fn decode_conn_id(buf: &mut Bytes) -> Result<Bytes, ParseError> {
    let len = buf[0] as usize;
    buf.advance(1);
    if len > 20 {
        // RFC 9000, 17.2: Connection ID MUST NOT exceed 20 bytes
        return Err(ParseError::NotValidQuicPacket);
    }
    if len > buf.remaining() {
        return Err(ParseError::NoEnoughData);
    }
    let id = buf.slice(0..len);
    buf.advance(id.len());
    Ok(id)
}

fn decode_var_int(buf: &mut Bytes) -> u64 {
    let len = 2u8.pow((buf[0] >> 6) as u32) as usize;
    let mut n = (buf[0] & 0b0011_1111) as u64;
    for i in 1..len {
        n = (n << 8) | buf[i] as u64;
    }
    buf.advance(len);
    n
}

#[test]
fn test_decode_var_int() {
    let mut buf = Bytes::copy_from_slice(&[0, 0x40, 0x47]);
    assert_eq!(decode_var_int(&mut buf), 0);
    assert_eq!(decode_var_int(&mut buf), 71);
}

#[test]
fn test_decode_packet() {
    let pkt = &hex_literal::hex!("""
        c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
        d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
        1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
        8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
        30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
        457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
        4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
        4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
        485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
        059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
        7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
        9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
        be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
        68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
        c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
        f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
        291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
        25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
        14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
        ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
        e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
        c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
        203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
        cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
        fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
        a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
        90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
        162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
        40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
        6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
        8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
        be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
        54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
        760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
        f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
        056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
        7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
        e221af44860018ab0856972e194cd934
    """);
    let expected_payload = &hex_literal::hex!("""
        060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
        04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
        616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
        04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
        baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
        0d0010000e0403050306030203080408 050806002d00020101001c0002400100
        3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
        75300901100f088394c8f03e51570806 048000ffff
    """);
    let pkt = InitialPacket::decode(Bytes::from_static(pkt)).unwrap();
    assert!(pkt.payload.starts_with(expected_payload));

    let msg = pkt.crypto_message().unwrap();
    assert_eq!(msg.remaining(), 241);
}
