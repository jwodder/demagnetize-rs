use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use thiserror::Error;

#[derive(Copy, Clone, Debug, EnumIter, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum Extension {
    AzureusMessaging = 63, // byte 0, 0x80 (BEP 4)
    LocationAware = 43,    // byte 2, 0x08 (BEP 4)
    Bep10 = 20,            // byte 5, 0x10 (BEP 10)
    Dht = 0,               // byte 7, 0x01 (BEP 4, BEP 5)
    XbtPex = 1,            // byte 7, 0x02 (BEP 4)
    Fast = 2,              // byte 7, 0x04 (BEP 4, BEP 6)
    NatTraversal = 3,      // byte 7, 0x08 (BEP 4)
    HybridV2 = 4,          // byte 7, 0x10 (BEP 4, BEP 52)
}

impl Extension {
    fn bit(self) -> u64 {
        1 << (self as u8)
    }
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Extension::*;
        match self {
            AzureusMessaging => write!(f, "Azureus Messaging Protocol"),
            LocationAware => write!(f, "BitTorrent Location-aware Protocol"),
            Bep10 => write!(f, "BEP 10 Extension Protocol"),
            Dht => write!(f, "BitTorrent DHT"),
            XbtPex => write!(f, "XBT Peer Exchange"),
            Fast => write!(f, "Fast Extension"),
            NatTraversal => write!(f, "NAT Traversal"),
            HybridV2 => write!(f, "hybrid torrent legacy to v2 upgrade"),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub(super) struct ExtensionSet(u64);

impl ExtensionSet {
    fn has(&self, ext: Extension) -> bool {
        self.0 & ext.bit() != 0
    }
}

impl fmt::Display for ExtensionSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut extset = self.0;
        let mut first = true;
        for ext in Extension::iter() {
            if extset & ext.bit() != 0 {
                if !std::mem::replace(&mut first, false) {
                    write!(f, ", ")?;
                }
                write!(f, "{ext}")?;
            }
            extset &= !ext.bit();
        }
        if extset != 0 {
            if !std::mem::replace(&mut first, false) {
                write!(f, ", ")?;
            }
            write!(f, "Unknown({extset:#018x})")?;
        }
        if first {
            write!(f, "<none>")?;
        }
        Ok(())
    }
}

impl From<ExtensionSet> for u64 {
    fn from(extset: ExtensionSet) -> u64 {
        extset.0
    }
}

impl From<u64> for ExtensionSet {
    fn from(extset: u64) -> ExtensionSet {
        ExtensionSet(extset)
    }
}

impl FromIterator<Extension> for ExtensionSet {
    fn from_iter<I>(iter: I) -> ExtensionSet
    where
        I: IntoIterator<Item = Extension>,
    {
        let mut value = 0;
        for ext in iter {
            value |= ext.bit();
        }
        ExtensionSet(value)
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum Bep10Extension {
    Metadata, // BEP 9
              //Pex,      // BEP 11
              //Holepunch,  // BEP 55
}

impl FromStr for Bep10Extension {
    type Err = Bep10Error;

    fn from_str(s: &str) -> Result<Bep10Extension, Bep10Error> {
        match s {
            "ut_metadata" => Ok(Bep10Extension::Metadata),
            //"ut_pex" => Ok(Bep10Extension::Pex),
            _ => Err(Bep10Error),
        }
    }
}

impl fmt::Display for Bep10Extension {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Bep10Extension::Metadata => write!(f, "ut_metadata"),
            //Bep10Extension::Pex => write!(f, "ut_pex"),
        }
    }
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
#[error("unknown extension dict key")]
pub(crate) struct Bep10Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Bep10Registry {
    to_code: HashMap<Bep10Extension, u8>,
    from_code: HashMap<u8, Bep10Extension>,
}

impl Bep10Registry {
    pub(super) fn new() -> Bep10Registry {
        Bep10Registry {
            to_code: HashMap::new(),
            from_code: HashMap::new(),
        }
    }

    pub(super) fn from_m(m: BTreeMap<String, u8>) -> Result<Bep10Registry, Bep10RegistryError> {
        let mut registry = Bep10Registry::new();
        for (k, v) in m {
            if let Ok(ext) = k.parse::<Bep10Extension>() {
                registry.register(ext, v)?;
            }
        }
        Ok(registry)
    }

    pub(super) fn to_m(&self) -> BTreeMap<String, u8> {
        let mut m = BTreeMap::new();
        for (&ext, &code) in &self.to_code {
            m.insert(ext.to_string(), code);
        }
        m
    }

    pub(super) fn contains(&self, ext: Bep10Extension) -> bool {
        self.to_code.contains_key(&ext)
    }

    pub(super) fn get_message_id(&self, ext: Bep10Extension) -> Option<u8> {
        self.to_code.get(&ext).copied()
    }

    pub(super) fn for_message_id(&self, code: u8) -> Option<Bep10Extension> {
        self.from_code.get(&code).copied()
    }

    pub(super) fn register(
        &mut self,
        ext: Bep10Extension,
        code: u8,
    ) -> Result<(), Bep10RegistryError> {
        if code == 0 {
            return Err(Bep10RegistryError::Handshake);
        }
        if self.from_code.contains_key(&code) {
            return Err(Bep10RegistryError::Code(code));
        }
        if self.to_code.contains_key(&ext) {
            return Err(Bep10RegistryError::Ext(ext));
        }
        let _prev_ext = self.from_code.insert(code, ext);
        debug_assert!(_prev_ext.is_none());
        let _prev_code = self.to_code.insert(ext, code);
        debug_assert!(_prev_code.is_none());
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum Bep10RegistryError {
    #[error("extended message ID 0 listed in \"m\"")]
    Handshake,
    #[error("extended message ID {0} listed in \"m\" more than once")]
    Code(u8),
    #[error("extension {0} listed in \"m\" more than once")]
    Ext(Bep10Extension),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_iter() {
        use Extension::*;
        let mut iter = Extension::iter();
        assert_eq!(iter.next(), Some(AzureusMessaging));
        assert_eq!(iter.next(), Some(LocationAware));
        assert_eq!(iter.next(), Some(Bep10));
        assert_eq!(iter.next(), Some(Dht));
        assert_eq!(iter.next(), Some(XbtPex));
        assert_eq!(iter.next(), Some(Fast));
        assert_eq!(iter.next(), Some(NatTraversal));
        assert_eq!(iter.next(), Some(HybridV2));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_extension_set() {
        let extset = [Extension::Bep10, Extension::Dht, Extension::Fast]
            .into_iter()
            .collect::<ExtensionSet>();
        assert!(extset.has(Extension::Bep10));
        assert!(extset.has(Extension::Dht));
        assert!(extset.has(Extension::Fast));
        assert!(!extset.has(Extension::LocationAware));
        assert!(!extset.has(Extension::XbtPex));
        assert_eq!(
            extset.to_string(),
            "BEP 10 Extension Protocol, BitTorrent DHT, Fast Extension"
        );
        assert_eq!(u64::from(extset), 0x100005);
        assert_eq!(ExtensionSet::from(0x100005u64), extset);
    }

    #[test]
    fn test_default_extension_set() {
        let extset = ExtensionSet::default();
        assert_eq!(u64::from(extset), 0);
        assert_eq!(ExtensionSet::from(0), extset);
        for ext in Extension::iter() {
            assert!(!extset.has(ext));
        }
        assert_eq!(extset.to_string(), "<none>");
    }

    #[test]
    fn test_extension_set_unknown() {
        let extset = ExtensionSet::from(0x8404u64);
        for ext in Extension::iter() {
            if ext == Extension::Fast {
                assert!(extset.has(ext));
            } else {
                assert!(!extset.has(ext));
            }
        }
        assert_eq!(
            extset.to_string(),
            "Fast Extension, Unknown(0x0000000000008400)"
        );
    }

    #[test]
    fn test_extension_set_all_unknown() {
        let extset = ExtensionSet::from(0x8400u64);
        for ext in Extension::iter() {
            assert!(!extset.has(ext));
        }
        assert_eq!(extset.to_string(), "Unknown(0x0000000000008400)");
    }
}
