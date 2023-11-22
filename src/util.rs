use bendy::decoding::{Decoder, FromBencode};
use bytes::{Buf, Bytes};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use thiserror::Error;

pub(crate) fn comma_list<T>(values: &[T]) -> CommaList<'_, T> {
    CommaList(values)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommaList<'a, T>(&'a [T]);

impl<T: fmt::Display> fmt::Display for CommaList<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for val in self.0 {
            if !std::mem::replace(&mut first, false) {
                write!(f, ", ")?;
            }
            write!(f, "{val}")?;
        }
        if first {
            write!(f, "<none>")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TryBytes(Bytes);

impl TryBytes {
    pub(crate) fn try_get<T: TryFromBuf>(&mut self) -> Result<T, PacketError> {
        T::try_from_buf(&mut self.0)
    }

    pub(crate) fn try_get_all<T: TryFromBuf>(mut self) -> Result<Vec<T>, PacketError> {
        let mut values = Vec::new();
        while self.0.has_remaining() {
            values.push(self.try_get()?);
        }
        Ok(values)
    }

    pub(crate) fn try_get_bytes(&mut self, len: usize) -> Result<Bytes, PacketError> {
        if self.0.len() >= len {
            Ok(self.0.copy_to_bytes(len))
        } else {
            Err(PacketError::Short)
        }
    }

    pub(crate) fn remainder(self) -> Bytes {
        self.0
    }

    pub(crate) fn eof(self) -> Result<(), PacketError> {
        if self.0.has_remaining() {
            Err(PacketError::Long)
        } else {
            Ok(())
        }
    }

    pub(crate) fn into_string_lossy(self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

impl From<Bytes> for TryBytes {
    fn from(bs: Bytes) -> TryBytes {
        TryBytes(bs)
    }
}

impl From<&[u8]> for TryBytes {
    fn from(bs: &[u8]) -> TryBytes {
        TryBytes::from(Bytes::from(bs.to_vec()))
    }
}

// All integers are read in big-endian order.
pub(crate) trait TryFromBuf: Sized {
    fn try_from_buf(buf: &mut Bytes) -> Result<Self, PacketError>;
}

macro_rules! impl_tryfrombuf {
    ($t:ty, $len:literal, $arg:ident, $get:expr) => {
        impl TryFromBuf for $t {
            fn try_from_buf($arg: &mut Bytes) -> Result<Self, PacketError> {
                if $arg.remaining() >= $len {
                    Ok($get)
                } else {
                    Err(PacketError::Short)
                }
            }
        }
    };
}

impl_tryfrombuf!(u8, 1, buf, buf.get_u8());
impl_tryfrombuf!(u16, 2, buf, buf.get_u16());
impl_tryfrombuf!(u32, 4, buf, buf.get_u32());
impl_tryfrombuf!(i32, 4, buf, buf.get_i32());
impl_tryfrombuf!(u64, 8, buf, buf.get_u64());
impl_tryfrombuf!(Ipv4Addr, 4, buf, buf.get_u32().into());
impl_tryfrombuf!(Ipv6Addr, 16, buf, buf.get_u128().into());

impl TryFromBuf for SocketAddrV4 {
    fn try_from_buf(buf: &mut Bytes) -> Result<Self, PacketError> {
        let ip = Ipv4Addr::try_from_buf(buf)?;
        let port = u16::try_from_buf(buf)?;
        Ok(SocketAddrV4::new(ip, port))
    }
}

impl TryFromBuf for SocketAddrV6 {
    fn try_from_buf(buf: &mut Bytes) -> Result<Self, PacketError> {
        let ip = Ipv6Addr::try_from_buf(buf)?;
        let port = u16::try_from_buf(buf)?;
        Ok(SocketAddrV6::new(ip, port, 0, 0))
    }
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum PacketError {
    #[error("unexpected end of packet")]
    Short,
    #[error("packet had trailing bytes")]
    Long,
}

// Like `FromBencode::from_bencode()`, but it checks that there are no trailing
// bytes afterwards
pub(crate) fn decode_bencode<T: FromBencode>(buf: &[u8]) -> Result<T, UnbencodeError> {
    let mut decoder = Decoder::new(buf).with_max_depth(T::EXPECTED_RECURSION_DEPTH);
    let value = match decoder.next_object()? {
        Some(obj) => T::decode_bencode_object(obj)?,
        None => return Err(UnbencodeError::NoData),
    };
    if !matches!(decoder.next_object(), Ok(None)) {
        return Err(UnbencodeError::TrailingData);
    }
    Ok(value)
}

// We can't derive `thiserror::Error` on this, as bendy's Error is not a
// standard Error.
#[derive(Clone, Debug)]
pub(crate) enum UnbencodeError {
    Bendy(bendy::decoding::Error),
    NoData,
    TrailingData,
}

impl fmt::Display for UnbencodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnbencodeError::Bendy(e) => write!(f, "{e}"),
            UnbencodeError::NoData => write!(f, "no data in bencode packet"),
            UnbencodeError::TrailingData => write!(f, "trailing bytes after bencode structure"),
        }
    }
}

impl From<bendy::decoding::Error> for UnbencodeError {
    fn from(e: bendy::decoding::Error) -> UnbencodeError {
        UnbencodeError::Bendy(e)
    }
}

impl std::error::Error for UnbencodeError {}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct ErrorChain<E>(pub(crate) E);

impl<E: std::error::Error> fmt::Display for ErrorChain<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(e) = source {
            write!(f, ": {e}")?;
            source = e.source();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comma_list() {
        assert_eq!(comma_list::<u32>(&[]).to_string(), "<none>");
        assert_eq!(comma_list(&[42]).to_string(), "42");
        assert_eq!(comma_list(&[42, 23]).to_string(), "42, 23");
        assert_eq!(comma_list(&[42, 23, 17]).to_string(), "42, 23, 17");
    }

    #[test]
    fn test_try_get_u8() {
        let mut buf = TryBytes::from(b"abc".as_slice());
        assert_eq!(buf.try_get::<u8>(), Ok(0x61));
        assert_eq!(buf.try_get::<u8>(), Ok(0x62));
        assert_eq!(buf.try_get::<u8>(), Ok(0x63));
        assert_eq!(buf.try_get::<u8>(), Err(PacketError::Short));
    }

    #[test]
    fn test_try_get_u16() {
        let mut buf = TryBytes::from(b"abc".as_slice());
        assert_eq!(buf.try_get::<u16>(), Ok(0x6162));
        assert_eq!(buf.try_get::<u16>(), Err(PacketError::Short));
    }

    #[test]
    fn test_try_get_u32() {
        let mut buf = TryBytes::from(b"0123abc".as_slice());
        assert_eq!(buf.try_get::<u32>(), Ok(0x30313233));
        assert_eq!(buf.try_get::<u32>(), Err(PacketError::Short));
    }

    #[test]
    fn test_try_get_i32() {
        let mut buf = TryBytes::from(b"\x80123abc".as_slice());
        assert_eq!(buf.try_get::<i32>(), Ok(-2144259533));
        assert_eq!(buf.try_get::<i32>(), Err(PacketError::Short));
    }

    #[test]
    fn test_try_get_u64() {
        let mut buf = TryBytes::from(b"01234567abcde".as_slice());
        assert_eq!(buf.try_get::<u64>(), Ok(0x3031323334353637));
        assert_eq!(buf.try_get::<u64>(), Err(PacketError::Short));
    }

    #[test]
    fn test_try_get_ipv4addr() {
        let mut buf = TryBytes::from(b"0123abc".as_slice());
        assert_eq!(
            buf.try_get::<Ipv4Addr>(),
            Ok(Ipv4Addr::new(0x30, 0x31, 0x32, 0x33))
        );
        assert_eq!(buf.try_get::<Ipv4Addr>(), Err(PacketError::Short));
    }

    #[test]
    fn test_try_get_ipv6addr() {
        let mut buf = TryBytes::from(b"iiiiiiiiiiiiiiii000000000".as_slice());
        assert_eq!(
            buf.try_get::<Ipv6Addr>(),
            Ok("6969:6969:6969:6969:6969:6969:6969:6969"
                .parse::<Ipv6Addr>()
                .unwrap())
        );
        assert_eq!(buf.try_get::<Ipv6Addr>(), Err(PacketError::Short));
    }

    #[test]
    fn test_try_get_socketaddrv4() {
        let mut buf = TryBytes::from(b"iiiipp0123".as_slice());
        assert_eq!(
            buf.try_get::<SocketAddrV4>(),
            Ok(SocketAddrV4::new(Ipv4Addr::new(105, 105, 105, 105), 28784))
        );
        assert_eq!(buf.try_get::<SocketAddrV4>(), Err(PacketError::Short));
    }

    #[test]
    fn test_try_get_socketaddrv6() {
        let mut buf = TryBytes::from(b"iiiiiiiiiiiiiiiipp012345678".as_slice());
        assert_eq!(
            buf.try_get::<SocketAddrV6>(),
            Ok("[6969:6969:6969:6969:6969:6969:6969:6969]:28784"
                .parse::<SocketAddrV6>()
                .unwrap())
        );
        assert_eq!(buf.try_get::<SocketAddrV6>(), Err(PacketError::Short));
    }
}
