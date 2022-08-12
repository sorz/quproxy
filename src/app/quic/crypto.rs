use hex_literal::hex;
use ring::{
    aead::{
        quic::{HeaderProtectionKey, AES_128},
        LessSafeKey, Nonce, UnboundKey, AES_128_GCM, NONCE_LEN,
    },
    hkdf::{KeyType, Prk, Salt, HKDF_SHA256},
};

const INITIAL_SALT: &[u8] = &hex!("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
const LABEL_CLIENT_IN: &[u8] = &hex!("00200f746c73313320636c69656e7420696e00");
const LABEL_QUIC_HP: &[u8] = &hex!("00100d746c733133207175696320687000");
const LABEL_QUIC_KEY: &[u8] = &hex!("00100e746c7331332071756963206b657900");
const LABEL_QUIC_IV: &[u8] = &hex!("000c0d746c733133207175696320697600");

pub(super) struct InitialSecret([u8; 32]);

impl InitialSecret {
    pub(super) fn new(dcid: &[u8]) -> Self {
        let init_key = Salt::new(HKDF_SHA256, INITIAL_SALT).extract(dcid);
        let client_in = init_key
            .expand(&[LABEL_CLIENT_IN], HKDF_SHA256)
            .expect("len too large");
        let mut key = [0u8; 32];
        client_in.fill(&mut key).unwrap();
        Self(key)
    }

    fn compute_iv(&self) -> [u8; NONCE_LEN] {
        let prk = Prk::new_less_safe(HKDF_SHA256, &self.0);
        let okm = prk.expand(&[LABEL_QUIC_IV], Iv).unwrap();
        let mut iv = [0u8; NONCE_LEN];
        okm.fill(&mut iv).unwrap();
        iv
    }

    pub(super) fn nonce(&self, pkt_no: u64) -> Nonce {
        let mut iv = self.compute_iv();
        iv.iter_mut()
            .rev()
            .zip(pkt_no.to_be_bytes().iter().rev())
            .for_each(|(k, n)| *k ^= n);
        Nonce::assume_unique_for_key(iv)
    }
}

impl From<&InitialSecret> for HeaderProtectionKey {
    fn from(init: &InitialSecret) -> Self {
        Prk::new_less_safe(HKDF_SHA256, &init.0)
            .expand(&[LABEL_QUIC_HP], &AES_128)
            .expect("len too large")
            .into()
    }
}

impl From<&InitialSecret> for LessSafeKey {
    fn from(InitialSecret(init): &InitialSecret) -> Self {
        let prk = Prk::new_less_safe(HKDF_SHA256, init);
        let okm = prk.expand(&[LABEL_QUIC_KEY], &AES_128_GCM).unwrap();
        let mut key = [0u8; 16];
        okm.fill(&mut key).unwrap();
        let key = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        LessSafeKey::new(key)
    }
}

struct Iv;

impl KeyType for Iv {
    fn len(&self) -> usize {
        NONCE_LEN
    }
}

#[test]
fn test_initial_keys() {
    let dcid = hex!("8394c8f03e515708");
    let sample = hex!("d1b1c98dd7689fb8ec11d242b123dc9b");
    // Header protection
    let init = InitialSecret::new(&dcid);
    let key: HeaderProtectionKey = (&init).into();
    assert_eq!(key.new_mask(&sample).unwrap(), hex!("437b9aec36"));
    // Payload: IV
    assert_eq!(&init.compute_iv(), &hex!("fa044b2f42a3fd3b46fb255c"));
    // Payload: Key
    let init = InitialSecret::new(&dcid);
    let key: LessSafeKey = (&init).into();
    // Payload: encryption
    let header = &hex!("c300000001088394c8f03e5157080000449e00000002");
    let frame = &hex!("""
        060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
        04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
        616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
        04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
        baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
        0d0010000e0403050306030203080408 050806002d00020101001c0002400100
        3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
        75300901100f088394c8f03e51570806 048000ffff
    """);
    let mut payload: bytes::BytesMut = frame.as_ref().into();
    payload.resize(1162, 0);
    let aad = ring::aead::Aad::from(header);
    let nonce = init.nonce(2);
    let tag = key
        .seal_in_place_separate_tag(nonce, aad, &mut payload)
        .unwrap();
    assert_eq!(&payload[..8], hex!("d1b1c98dd7689fb8"));
    assert_eq!(tag.as_ref(), hex!("e221af44860018ab0856972e194cd934"));
}
