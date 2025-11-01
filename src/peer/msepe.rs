use super::Peer;
use crate::types::InfoHash;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use generic_array::GenericArray;
use num_bigint::BigUint;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rand::Rng;
use rc4::{KeyInit, Rc4, StreamCipher, consts::U20};
use sha1::{Digest, Sha1};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::{Instant, timeout_at},
};

pub(crate) const DEFAULT_DH_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

const DEFAULT_CRYPTO_PROVIDE: [CryptoMethod; 1] = [CryptoMethod::Rc4];

const MODULUS_BYTES: usize = 96;

const MIN_PACKET2_LEN: usize = MODULUS_BYTES;

const MAX_PACKET2_LEN: usize = 608;

#[derive(
    Clone, Copy, Debug, Eq, Hash, IntoPrimitive, Ord, PartialEq, PartialOrd, TryFromPrimitive,
)]
#[repr(u32)]
pub(crate) enum CryptoMethod {
    Plaintext = 0x01,
    Rc4 = 0x02,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CryptoMethodSet(u32);

impl CryptoMethodSet {
    fn contains(&self, method: CryptoMethod) -> bool {
        self.0 & u32::from(method) != 0
    }
}

impl FromIterator<CryptoMethod> for CryptoMethodSet {
    fn from_iter<I: IntoIterator<Item = CryptoMethod>>(iter: I) -> CryptoMethodSet {
        let ored = iter.into_iter().fold(0u32, |acc, m| acc | u32::from(m));
        CryptoMethodSet(ored)
    }
}

impl From<CryptoMethodSet> for u32 {
    fn from(value: CryptoMethodSet) -> u32 {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HandshakeBuilder<R> {
    peer: Peer,
    skey: InfoHash,
    rng: R,
    crypto_provide: CryptoMethodSet,
    timeout: Duration,
}

impl<R: Rng> HandshakeBuilder<R> {
    pub(super) fn new(peer: Peer, skey: InfoHash, rng: R) -> Self {
        HandshakeBuilder {
            peer,
            skey,
            rng,
            crypto_provide: CryptoMethodSet::from_iter(DEFAULT_CRYPTO_PROVIDE),
            timeout: DEFAULT_DH_EXCHANGE_TIMEOUT,
        }
    }

    /*
    pub(super) fn crypto_provide<I: IntoIterator<Item = CryptoMethod>>(
        mut self,
        methods: I,
    ) -> Self {
        self.crypto_provide = CryptoMethodSet::from_iter(methods);
        self
    }
    */

    pub(super) fn dh_exchange_timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    fn build(self) -> Handshaker {
        let mut rng = self.rng;
        let pada_len = rng.random_range(..=512);
        let padc_len = rng.random_range(..=512);
        let private_key = gen_private_key(&mut rng);
        let pubkey = BigUint::from(2usize).modpow(&private_key, &prime_modulus());
        let mut packet1 = BytesMut::with_capacity(MODULUS_BYTES + pada_len);
        packet1.extend(biguint2bytes(&pubkey));
        packet1.extend(rng.random_iter::<u8>().take(pada_len));
        Handshaker {
            peer: self.peer,
            state: HandshakeState::Packet2 { private_key },
            output_packet: Some(packet1.freeze()),
            padc_len,
            skey: self.skey,
            timeout: Some(self.timeout),
            input_buffer: BytesMut::new(),
            crypto_provide: self.crypto_provide,
        }
    }
}

struct Handshaker {
    peer: Peer,
    state: HandshakeState,
    output_packet: Option<Bytes>,
    padc_len: u16,
    skey: InfoHash,
    timeout: Option<Duration>,
    input_buffer: BytesMut,
    crypto_provide: CryptoMethodSet,
}

impl Handshaker {
    /// Returns bytes to send to the server
    ///
    /// - On first call: Returns packet 1
    /// - On next call after `handle_timeout()` is called: Returns packet 3
    fn get_output(&mut self) -> Option<Bytes> {
        self.output_packet.take()
    }

    /// Passed bytes received from the server
    fn handle_input<B: Buf>(&mut self, b: B) -> Result<(), HandshakeError> {
        self.input_buffer.put(b);
        if let HandshakeState::Packet4 {
            substate,
            rc4_keystream,
        } = &mut self.state
        {
            loop {
                match (&mut *substate, self.input_buffer.len()) {
                    (Packet4State::Vc, 0..8) => break,
                    (Packet4State::Vc, _) => {
                        let mut vc = self.input_buffer.split_to(8);
                        rc4_keystream.decode(vc.as_mut());
                        if !vc.into_iter().all(|b| b == 0) {
                            return Err(HandshakeError::VcNotZero);
                        }
                        *substate = Packet4State::Select;
                    }
                    (Packet4State::Select, 0..4) => break,
                    (Packet4State::Select, _) => {
                        let mut cs = self.input_buffer.split_to(4);
                        rc4_keystream.decode(cs.as_mut());
                        let cs = cs.get_u32();
                        let selections = cs.count_ones();
                        if selections != 1 {
                            return Err(HandshakeError::SelectNotSingle(selections));
                        }
                        let Ok(crypto_select) = CryptoMethod::try_from(cs) else {
                            return Err(HandshakeError::UnknownMethod(cs));
                        };
                        if !self.crypto_provide.contains(crypto_select) {
                            return Err(HandshakeError::UnexpectedSelection(crypto_select));
                        }
                        log::trace!("{} selected encryption method {crypto_select:?}", self.peer);
                        *substate = Packet4State::LenPadD { crypto_select };
                    }
                    (Packet4State::LenPadD { .. }, 0..2) => break,
                    (Packet4State::LenPadD { crypto_select }, _) => {
                        let mut buf = self.input_buffer.split_to(2);
                        rc4_keystream.decode(buf.as_mut());
                        let bytes_needed = usize::from(buf.get_u16());
                        *substate = Packet4State::PadD {
                            crypto_select: *crypto_select,
                            bytes_needed,
                        };
                    }
                    (
                        Packet4State::PadD {
                            bytes_needed,
                            crypto_select,
                        },
                        bytes_avail,
                    ) => {
                        let sz = (*bytes_needed).min(bytes_avail);
                        let mut padd = self.input_buffer.split_to(sz);
                        rc4_keystream.decode(padd.as_mut());
                        *bytes_needed -= sz;
                        if *bytes_needed == 0 {
                            let keystream = match crypto_select {
                                CryptoMethod::Plaintext => Keystream::Plaintext,
                                CryptoMethod::Rc4 => std::mem::take(rc4_keystream),
                            };
                            log::debug!("Encryption handshake with {} complete", self.peer);
                            self.state = HandshakeState::Done { keystream };
                        }
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns the amount of time after which `handle_timeout()` should be
    /// called; only returns `Some` on first call
    fn get_timeout(&mut self) -> Option<Duration> {
        self.timeout.take()
    }

    /// Called once the timeout from `get_timeout()` has expired, thereby
    /// indicating that the receipt of packet 2 is complete
    fn handle_timeout(&mut self) -> Result<(), HandshakeError> {
        if let HandshakeState::Packet2 { ref private_key } = self.state {
            let mut packet2 = std::mem::take(&mut self.input_buffer);
            let sz = packet2.len();
            if !(MIN_PACKET2_LEN..=MAX_PACKET2_LEN).contains(&sz) {
                return Err(HandshakeError::Packet2Len(sz));
            }
            packet2.truncate(MODULUS_BYTES);
            let server_pubkey = BigUint::from_bytes_be(packet2.as_ref());
            let shared_secret = server_pubkey.modpow(private_key, &prime_modulus());
            let shared_secret = biguint2bytes(&shared_secret);
            // TODO: Securely discard private_key

            let mut key_a = BytesMut::with_capacity(4 + MODULUS_BYTES + InfoHash::LENGTH);
            key_a.extend_from_slice(b"keyA");
            key_a.extend_from_slice(&shared_secret);
            key_a.extend_from_slice(self.skey.as_bytes());
            let hash_a = hash(key_a);

            let mut key_b = BytesMut::with_capacity(4 + MODULUS_BYTES + InfoHash::LENGTH);
            key_b.extend_from_slice(b"keyB");
            key_b.extend_from_slice(&shared_secret);
            key_b.extend_from_slice(self.skey.as_bytes());
            let hash_b = hash(key_b);

            let mut rc4_outgoing = Rc4::new(&hash_a);
            let mut rc4_incoming = Rc4::new(&hash_b);
            let mut deadhead = vec![0u8; 1024];
            // Discard first 1024 bytes of each keystream:
            rc4_outgoing.apply_keystream(&mut deadhead);
            rc4_incoming.apply_keystream(&mut deadhead);

            /*
            let IA = b"";
            let VC = b"\0" * 8;
            let packet3 =
                HASH("req1" + shared_secret)
                + (HASH("req2" + skey) XOR HASH("req3" + shared_secret))
                + RC4(VC + crypto_provide + len(PadC) + PadC + len(IA) + IA)
            */

            let padc_usize = usize::from(self.padc_len);
            let mut packet3 = BytesMut::with_capacity(20 + 20 + 8 + 4 + 2 + padc_usize + 2);

            let mut req1 = BytesMut::with_capacity(4 + MODULUS_BYTES);
            req1.extend_from_slice(b"req1");
            req1.extend_from_slice(&shared_secret);
            packet3.extend(hash(req1));

            let mut req2 = BytesMut::with_capacity(4 + InfoHash::LENGTH);
            req2.extend_from_slice(b"req2");
            req2.extend_from_slice(self.skey.as_bytes());
            let hash2 = hash(req2);

            let mut req3 = BytesMut::with_capacity(4 + MODULUS_BYTES);
            req3.extend_from_slice(b"req3");
            req3.extend_from_slice(&shared_secret);
            let hash3 = hash(req3);

            packet3.extend(std::iter::zip(hash2, hash3).map(|(a, b)| a ^ b));

            let mut outgoing = BytesMut::with_capacity(8 + 4 + 2 + padc_usize + 2);
            outgoing.put_bytes(0, 8);
            outgoing.put_u32(self.crypto_provide.into());
            outgoing.put_u16(self.padc_len);
            outgoing.put_bytes(0, padc_usize);
            outgoing.put_u16(0);
            rc4_outgoing.apply_keystream(&mut outgoing);
            packet3.extend(outgoing);

            self.output_packet = Some(packet3.freeze());
            self.state = HandshakeState::Packet4 {
                rc4_keystream: Keystream::Rc4 {
                    outgoing: rc4_outgoing,
                    incoming: rc4_incoming,
                },
                substate: Packet4State::Vc,
            };
        }
        // Else (called too many times): Error?  Do nothing?
        Ok(())
    }

    /// Returns whether the handshake is complete (i.e., all of packet 4 has been received)
    fn done(&self) -> bool {
        matches!(self.state, HandshakeState::Done { .. })
    }

    /// Returns the final keystream and any initial encrypted data received after packet 4
    fn into_keystream(self) -> (Keystream, Bytes) {
        if let Handshaker {
            state: HandshakeState::Done { keystream },
            input_buffer,
            ..
        } = self
        {
            (keystream, input_buffer.freeze())
        } else {
            panic!("Handshaker::into_keystream() called before handshake completed");
        }
    }
}

enum HandshakeState {
    Packet2 {
        private_key: BigUint,
    },
    Packet4 {
        rc4_keystream: Keystream,
        substate: Packet4State,
    },
    Done {
        keystream: Keystream,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Packet4State {
    /// Waiting for VC (initial 8 bytes of packet 4)
    Vc,
    /// Waiting for `crypto_select` (next 4 bytes of packet 4)
    Select,
    /// Waiting for `len(PadD)` (next 2 bytes of packet 4)
    LenPadD { crypto_select: CryptoMethod },
    /// Receiving contents of `PadD`
    PadD {
        crypto_select: CryptoMethod,
        bytes_needed: usize,
    },
}

#[derive(Debug, Error)]
pub(crate) enum HandshakeError {
    #[error("initial crypto handshake packet from server had invalid length: {0} bytes")]
    Packet2Len(usize),
    #[error("received invalid verification constant in crypto handshake")]
    VcNotZero,
    #[error("server selected {0} crypto methods instead of exactly 1")]
    SelectNotSingle(u32),
    #[error("server selected unknown crypto method {0:#x}")]
    UnknownMethod(u32),
    #[error("server selected crypto method {0:?} even though we didn't ask for it")]
    UnexpectedSelection(CryptoMethod),
    #[error("error sending message to peer")]
    Send(#[source] std::io::Error),
    #[error("error receiving message from peer")]
    Recv(#[source] std::io::Error),
    #[error("peer suddenly disconnected")]
    Disconnect,
}

#[derive(Default)]
#[allow(clippy::large_enum_variant)]
enum Keystream {
    #[default]
    Plaintext,
    Rc4 {
        outgoing: Rc4<U20>,
        incoming: Rc4<U20>,
    },
}

impl Keystream {
    /// Encode data before sending it to the server
    fn encode(&mut self, bs: &mut [u8]) {
        if let Keystream::Rc4 { outgoing, .. } = self {
            outgoing.apply_keystream(bs);
        }
    }

    /// Decode incoming data received from the server
    fn decode(&mut self, bs: &mut [u8]) {
        if let Keystream::Rc4 { incoming, .. } = self {
            incoming.apply_keystream(bs);
        }
    }
}

pin_project_lite::pin_project! {
    pub(super) struct EncryptedStream {
        #[pin]
        inner: TcpStream,
        keystream: Keystream,
        // Bytes sent from the server after packet 4 that were received during the
        // handshake and that now need to be decrypted & returned via the
        // `AsyncRead` impl
        read_buffer: Bytes,
        // Encoded bytes to send to the server on flush
        write_buffer: BytesMut,
    }
}

impl EncryptedStream {
    pub(super) async fn handshake<R: Rng>(
        mut conn: TcpStream,
        config: HandshakeBuilder<R>,
    ) -> Result<Self, HandshakeError> {
        let mut handshaker = config.build();
        let mut timeout_time = None;
        let mut n = 1;
        while !handshaker.done() {
            if let Some(mut outgoing) = handshaker.get_output() {
                log::trace!(
                    "Sending encryption handshake packet {n} to {}",
                    handshaker.peer
                );
                n += 2;
                conn.write_all_buf(&mut outgoing)
                    .await
                    .map_err(HandshakeError::Send)?;
                conn.flush().await.map_err(HandshakeError::Send)?;
            }
            if let Some(timeout_len) = handshaker.get_timeout() {
                timeout_time = Some(Instant::now() + timeout_len);
            }
            let mut buf = BytesMut::with_capacity(65535);
            let fut = conn.read_buf(&mut buf);
            let r = if let Some(deadline) = timeout_time {
                timeout_at(deadline, fut).await.ok()
            } else {
                Some(fut.await)
            };
            match r {
                Some(Ok(0)) => return Err(HandshakeError::Disconnect),
                Some(Ok(_)) => handshaker.handle_input(buf)?,
                Some(Err(e)) => return Err(HandshakeError::Recv(e)),
                None => {
                    log::trace!(
                        "Finished receiving encryption handshake packet 2 from {}",
                        handshaker.peer
                    );
                    timeout_time = None;
                    handshaker.handle_timeout()?;
                }
            }
        }
        let (keystream, read_buffer) = handshaker.into_keystream();
        Ok(EncryptedStream {
            inner: conn,
            keystream,
            read_buffer,
            write_buffer: BytesMut::new(),
        })
    }
}

impl AsyncRead for EncryptedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let prelen = buf.filled().len();
        let r = if !this.read_buffer.is_empty() {
            let sz = buf.remaining().min(this.read_buffer.len());
            let bs = this.read_buffer.split_to(sz);
            buf.put_slice(bs.as_ref());
            Ok(())
        } else {
            ready!(this.inner.poll_read(cx, buf))
        };
        if r.is_ok() && buf.filled().len() > prelen {
            this.keystream.decode(&mut buf.filled_mut()[prelen..]);
        }
        r.into()
    }
}

impl AsyncWrite for EncryptedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let prelen = this.write_buffer.len();
        this.write_buffer.extend_from_slice(buf);
        this.keystream
            .encode(&mut this.write_buffer.as_mut()[prelen..]);
        Ok(buf.len()).into()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        while !this.write_buffer.is_empty() {
            let written = ready!(
                this.inner
                    .as_mut()
                    .poll_write(cx, this.write_buffer.as_ref())
            )?;
            let _ = this.write_buffer.split_to(written);
        }
        this.inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

fn hash<S: AsRef<[u8]>>(bs: S) -> GenericArray<u8, U20> {
    Sha1::digest(bs)
}

fn gen_private_key<R: Rng>(rng: &mut R) -> BigUint {
    /*
        // Post-<https://github.com/rust-num/num-bigint/pull/322>:
        // Requires "rand" feature of num_bigint
        use num_bigint::RandBigInt;
        rng.random_biguint(160)
    */
    let bytes = rng.random_iter::<u8>().take(20).collect::<Vec<_>>();
    BigUint::from_bytes_be(&bytes)
}

fn prime_modulus() -> BigUint {
    BigUint::parse_bytes(
        concat!(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74",
            "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437",
            "4fe1356d6d51c245e485b576625e7ec6f44c42e9a63a36210000000000090563",
        )
        .as_bytes(),
        16,
    )
    .expect("prime modulus string should be valid")
}

fn biguint2bytes(bi: &BigUint) -> Vec<u8> {
    let mut bytes = bi.to_bytes_be();
    if let Some(deficit) = MODULUS_BYTES.checked_sub(bytes.len()) {
        let mut bytes2 = vec![0u8; deficit];
        bytes2.append(&mut bytes);
        bytes = bytes2;
    }
    debug_assert_eq!(
        bytes.len(),
        MODULUS_BYTES,
        "encoded DH integer should be same size as modulus"
    );
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prime_modulus() {
        // Test that it doesn't panic
        let _ = prime_modulus();
    }

    mod handshake {
        use super::*;
        use data_encoding::HEXLOWER_PERMISSIVE;
        use rand::SeedableRng;
        use rand_chacha::ChaCha12Rng;

        const RNG_SEED: u64 = 0x0123456789ABCDEF;
        static INFO_HASH: &str = "28c55196f57753c40aceb6fb58617e6995a7eddb";
        static PRIVATE_KEY: &str = "a068078feb542e953c13e4dacece2b6730a2b512";
        static PUBLIC_KEY: &str = "fe0ffefc8a55947c7054729257d361deffc0f235bd0401acf283c4a34d0d38b7fc183fc4b172e74eed2226c9b58337605448b8217a036b740886c49578963c8ef1e1211da94f3e1386a9a6f82e8e54156de0fc5897b3a84a6d8108492cc38b6a";
        static SERVER_PUBKEY: &str = "b5816983bb486213388ea0ce7d8069cb62e8333a81eade46313590ff40ac185faeae22b28d4460341fa519171a15343844b80904e2e772bcc9dd8964586bdd08bb3ce6941a82dc1d305f7c8f771119f1b3c6f0d34a74f22b726d94b453b878fb";
        const PADC_LEN: u16 = 379;

        fn hex2uint(hexstr: &str) -> BigUint {
            BigUint::parse_bytes(hexstr.as_bytes(), 16).unwrap()
        }

        fn hex2bytes(hexstr: &str) -> BytesMut {
            BytesMut::from_iter(HEXLOWER_PERMISSIVE.decode(hexstr.as_bytes()).unwrap())
        }

        #[test]
        fn test_build() {
            let peer = "127.0.0.1:60069".parse::<Peer>().unwrap();
            let info_hash = INFO_HASH.parse::<InfoHash>().unwrap();
            let builder =
                HandshakeBuilder::new(peer, info_hash, ChaCha12Rng::seed_from_u64(RNG_SEED));
            let mut shaker = builder.build();
            assert_eq!(shaker.peer, peer);
            let HandshakeState::Packet2 { ref private_key } = shaker.state else {
                panic!("Handshaker state is not Packet2");
            };
            assert_eq!(private_key, &hex2uint(PRIVATE_KEY));
            let output1 = shaker.output_packet.clone();
            assert_eq!(shaker.get_output(), output1);
            assert_eq!(shaker.output_packet, None);
            assert_eq!(shaker.get_output(), None);
            let packet1 = output1.unwrap();
            let pubkey = BigUint::from_bytes_be(&packet1[..MODULUS_BYTES]);
            assert_eq!(pubkey, hex2uint(PUBLIC_KEY));
            assert!(((MODULUS_BYTES)..(MODULUS_BYTES + 512)).contains(&packet1.len()));
            assert_eq!(shaker.padc_len, PADC_LEN);
            assert_eq!(shaker.skey, info_hash);
            assert_eq!(shaker.timeout, Some(DEFAULT_DH_EXCHANGE_TIMEOUT));
            assert_eq!(shaker.get_timeout(), Some(DEFAULT_DH_EXCHANGE_TIMEOUT));
            assert_eq!(shaker.timeout, None);
            assert_eq!(shaker.get_timeout(), None);
            assert_eq!(shaker.input_buffer, BytesMut::new());
            assert_eq!(
                shaker.crypto_provide,
                CryptoMethodSet::from_iter(DEFAULT_CRYPTO_PROVIDE)
            );
        }

        #[test]
        fn test_build_custom_timeout() {
            let peer = "127.0.0.1:60069".parse::<Peer>().unwrap();
            let info_hash = INFO_HASH.parse::<InfoHash>().unwrap();
            let builder = HandshakeBuilder::new(
                peer,
                info_hash,
                ChaCha12Rng::seed_from_u64(0x0123456789ABCDEF),
            )
            .dh_exchange_timeout(Duration::from_secs(5));
            let mut shaker = builder.build();
            assert_eq!(shaker.timeout, Some(Duration::from_secs(5)));
            assert_eq!(shaker.get_timeout(), Some(Duration::from_secs(5)));
            assert_eq!(shaker.timeout, None);
            assert_eq!(shaker.get_timeout(), None);
        }

        #[test]
        fn test_handshake() {
            let peer = "127.0.0.1:60069".parse::<Peer>().unwrap();
            let info_hash = INFO_HASH.parse::<InfoHash>().unwrap();
            let builder =
                HandshakeBuilder::new(peer, info_hash, ChaCha12Rng::seed_from_u64(RNG_SEED));
            let mut shaker = builder.build();
            assert!(shaker.get_output().is_some());
            assert!(shaker.get_timeout().is_some());
            let mut packet2 = hex2bytes(SERVER_PUBKEY);
            packet2.put_bytes(0, 123);
            assert!(shaker.handle_input(packet2).is_ok());
            assert!(shaker.handle_timeout().is_ok());
            let packet3 = shaker.get_output().unwrap();
            assert_eq!(shaker.get_timeout(), None);
            assert_eq!(
                packet3,
                hex2bytes(concat!(
                    "8e34baff908570c95d7ac86a8cbd66bca97559ba90eb626d8887c8f0",
                    "1e6239809baa3be4a8b20aa71767de7f5409d59790a6ea2305d73ab2",
                    "946572e9095be91d082f6b1e589dd086265ab55472d059285e82b7c5",
                    "532736ffb2ab384615c9ebb77305224f3bc475a9d5a54b867c3c19da",
                    "f105d52d1283107d0a82091b4cce1d33c2733f884cee790daadbeeaf",
                    "4b415bf431d9c259de7a01e348b6629191502c46adf815a366f725a3",
                    "0cafedf3cacb4bd1230280e59f6c85e8bb80db4c83d6ec7139351512",
                    "db13d739073f21310f9fd72cf0f8b7b5874ce034b654e5c360fb5d4b",
                    "c0b4e26c289462627e32d0e76fe0b036720aa447908a83ed5c33894c",
                    "33467031777d94420dc5894a45446a1c54c421b0ba91fedc591e3a64",
                    "b4fa644080ae509757c41e6a10d3e360cb5ced64ad29587f54f655dc",
                    "0cc9cf7fca4f4f85b63b594e20121a7c3e0d5026f68440324f420e0d",
                    "086678d89e530e77d44ab68b13c5f7dc7e08a43e198640e608200582",
                    "3446ec6ca0a796611247ae2f2f2457c611f8dde116490e6d4497af80",
                    "af19676320545afecced4dd6c1f46ee0fbfb9ad77172e13bfff4a8f7",
                    "e75e2608cd7d7b437368a33e40d208",
                ))
            );
            let packet4 = hex2bytes(concat!(
                "997fd11c26fca76561f2731f5ca125bef92cdde3a41fbdcb5462f7d6b6bc",
                "a93d7235c29d5eb847408d1b899472b455645325ab28cf7e0f76",
            ));
            assert!(shaker.handle_input(packet4).is_ok());
            assert!(shaker.done());
            let (mut keystream, extra) = shaker.into_keystream();
            assert!(extra.is_empty());
            let mut outgoing = BytesMut::from("Hello, World!");
            keystream.encode(outgoing.as_mut());
            assert_eq!(outgoing, hex2bytes("825807e21b9faa9dd6e4fb3cac"));
            let mut incoming = BytesMut::from("Guten Tag, Welt!");
            keystream.decode(incoming.as_mut());
            assert_eq!(incoming, hex2bytes("4fab277eea46010cf84c296afc116ea3"));
        }
    }
}
