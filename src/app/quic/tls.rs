use bytes::Buf;
use tracing::debug;

macro_rules! pkt_assert {
    ($e:expr, $err:expr) => {
        if !$e {
            debug!("Failed to get SNI: {}", $err);
            return None;
        }
    };
}

macro_rules! impl_get {
    ($t:ident, $get:ident) => {
        fn $get(&mut self) -> Option<$t> {
            if !self.inner.has_remaining() {
                None
            } else {
                Some(self.inner.$get())
            }
        }
    };
}

struct Reader<T: Buf> {
    inner: T,
}

impl<T: Buf> Reader<T> {
    fn new(buf: T) -> Self {
        Self { inner: buf }
    }

    fn advance(&mut self, cnt: usize) -> Option<()> {
        if self.inner.remaining() < cnt {
            None
        } else {
            self.inner.advance(cnt);
            Some(())
        }
    }

    impl_get!(u8, get_u8);
    impl_get!(u16, get_u16);
}

pub(super) fn get_server_name_from_client_hello<T: Buf>(buf: T) -> Option<String> {
    let mut buf = Reader::new(buf);
    pkt_assert!(buf.get_u8()? == 0x01, "Type != ClientHello");
    let len = (buf.get_u8()? as usize) << 8 | (buf.get_u16()? as usize);
    pkt_assert!(len == buf.inner.remaining(), "length mismatched");
    buf.advance(2)?; // Legacy version
    buf.advance(32)?; // Random
    let len = buf.get_u8()? as usize; // Legacy session ID
    buf.advance(len)?;
    let len = buf.get_u16()? as usize; // Cipher suit
    buf.advance(len)?;
    pkt_assert!(
        buf.get_u16()? == 0x0100,
        "Legacy compression methods != null"
    );
    let len = buf.get_u16()? as usize; // Extension
    pkt_assert!(buf.inner.remaining() == len, "Extension length mismatched");

    while buf.inner.has_remaining() {
        let tag = buf.get_u16()?;
        let len = buf.get_u16()? as usize;
        pkt_assert!(buf.inner.remaining() >= len, "Truncted extension");
        match tag {
            0x0000 => {
                // SNI
                let mut ext_len = buf.get_u16()? as usize;
                pkt_assert!(ext_len <= len - 2, "Truncted SNI");
                while ext_len > 3 {
                    let name_type = buf.get_u8()?;
                    let name_len = buf.get_u16()? as usize;
                    ext_len -= 3;
                    pkt_assert!(name_len <= ext_len, "Truncted SNI list");
                    match name_type {
                        0x0000 => {
                            // Hostname
                            pkt_assert!(name_len > 0, "Zero-sized server name");
                            let mut name_buf = vec![0u8; name_len];
                            buf.inner.copy_to_slice(&mut name_buf);
                            let name = String::from_utf8(name_buf).ok()?;
                            let valid = name
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() | "-._".contains(c));
                            pkt_assert!(valid, "Domain name contains illegal character");
                            return Some(name);
                        }
                        _ => {
                            // Ignore other types
                            buf.advance(name_len);
                            ext_len -= name_len;
                        }
                    }
                }
                buf.advance(ext_len);
            }
            _ => {
                // Ignore other extension
                buf.advance(len);
            }
        }
    }
    None
}

#[test]
fn test_parse_client_hello() {
    let buf = &hex_literal::hex!("""
        0100011e03032d9a20d602eadf5581c4 3119415208653176e86fb0c535c8a0c3
        aa8742dc65c300000613011302130301 0000ef00390060fb5c27d8ca3e448804
        a09432370f00030245c080ff73db0c00 0000018aaa3a0a000000017127048002
        ae500802406409024067040480f00000 06048060000001048000753020048001
        00000704806000008000475204000000 01050480600000001000050003026833
        00000013001100000e7777772e676f6f 676c652e636f6d000a00080006001d00
        170018002d0002010100330026002400 1d00203e65bd93cf09572df162e5e1f1
        e67c2aa7a2c25faa35d289a422aa2462 e24a47000d0014001204030804040105
        0308050501080606010201001b000302 0002002b000302030444690005000302
        6833
    """);
    let name = get_server_name_from_client_hello(bytes::Bytes::from_static(buf)).unwrap();
    assert_eq!(&name, "www.google.com")
}
