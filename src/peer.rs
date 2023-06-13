use crate::types::PeerId;
use std::fmt;
use std::net::{AddrParseError, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Peer {
    address: SocketAddr,
    id: Option<PeerId>,
}

impl FromStr for Peer {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Peer, AddrParseError> {
        let address = s.parse::<SocketAddr>()?;
        Ok(Peer { address, id: None })
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<Peer {}>", self.address)
    }
}

impl From<SocketAddrV4> for Peer {
    fn from(addr: SocketAddrV4) -> Peer {
        Peer {
            address: addr.into(),
            id: None,
        }
    }
}

impl From<SocketAddrV6> for Peer {
    fn from(addr: SocketAddrV6) -> Peer {
        Peer {
            address: addr.into(),
            id: None,
        }
    }
}
