use crate::consts::{CLIENT, MAX_INFO_LENGTH};
use crate::tracker::Tracker;
use crate::types::InfoHash;
use bendy::decoding::{Decoder, Object};
use bendy::encoding::ToBencode;
use bytes::{BufMut, Bytes, BytesMut};
use sha1::{Digest, Sha1};
use std::borrow::Cow;
use std::iter::{repeat, Peekable};
use std::ops::Range;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TorrentInfo {
    info_hash: InfoHash,
    data: Bytes,
}

impl TorrentInfo {
    pub(crate) fn name(&self) -> Option<Cow<'_, str>> {
        let mut decoder = Decoder::new(&self.data);
        let Ok(Some(obj)) = decoder.next_object() else {
            unreachable!();
        };
        let mut dd = obj
            .try_into_dictionary()
            .expect("Torrent info should be a dict");
        while let Some(kv) = dd.next_pair().ok()? {
            if let (b"name", v) = kv {
                return Some(String::from_utf8_lossy(v.try_into_bytes().ok()?));
            }
        }
        None
    }
}

impl From<TorrentInfo> for Bytes {
    fn from(info: TorrentInfo) -> Bytes {
        info.data
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TorrentInfoBuilder {
    info_hash: InfoHash,
    hasher: Sha1,
    data: BytesMut,
    sizes: Vec<usize>,
    index_iter: Peekable<Range<u32>>,
}

impl TorrentInfoBuilder {
    const PIECE_LENGTH: usize = 16 << 10; // 16 KiB

    pub(crate) fn new(
        info_hash: InfoHash,
        length: u32,
    ) -> Result<TorrentInfoBuilder, ConstructError> {
        let Ok(lgth) = usize::try_from(length) else {
            return Err(ConstructError::TooLarge(length));
        };
        if lgth > MAX_INFO_LENGTH {
            return Err(ConstructError::TooLarge(length));
        }
        let hasher = Sha1::new();
        let data = BytesMut::with_capacity(lgth);
        let mut sizes = repeat(Self::PIECE_LENGTH)
            .take(lgth / Self::PIECE_LENGTH)
            .collect::<Vec<_>>();
        let overflow = lgth % Self::PIECE_LENGTH;
        if overflow > 0 {
            sizes.push(overflow);
        }
        let piece_qty = u32::try_from(sizes.len()).unwrap();
        Ok(TorrentInfoBuilder {
            info_hash,
            hasher,
            data,
            sizes,
            index_iter: (0..piece_qty).peekable(),
        })
    }

    pub(crate) fn push(&mut self, piece: Bytes) -> Result<(), PushError> {
        let Some(index) = self.index_iter.next() else {
            return Err(PushError::TooManyPieces);
        };
        let index = usize::try_from(index).unwrap();
        if piece.len() != self.sizes[index] {
            return Err(PushError::Length {
                index,
                expected: self.sizes[index],
                got: piece.len(),
            });
        }
        self.hasher.update(&piece);
        self.data.extend(piece);
        Ok(())
    }

    pub(crate) fn piece_qty(&self) -> usize {
        self.sizes.len()
    }

    pub(crate) fn next_piece(&mut self) -> Option<u32> {
        self.index_iter.peek().copied()
    }

    pub(crate) fn build(self) -> Result<TorrentInfo, BuildError> {
        let left = self.index_iter.count();
        if left > 0 {
            return Err(BuildError::NotFinished { left });
        }
        let got_hash = Bytes::from(self.hasher.finalize().to_vec());
        if got_hash != self.info_hash.as_bytes() {
            return Err(BuildError::Digest {
                expected: self.info_hash,
                got: got_hash,
            });
        }
        let data = self.data.freeze();
        check_bencode_dict(&data)?;
        Ok(TorrentInfo {
            info_hash: self.info_hash,
            data,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TorrentFile {
    info: TorrentInfo,
    trackers: Vec<Tracker>,
    creation_date: i64,
    created_by: String,
}

impl TorrentFile {
    pub(crate) fn new(info: TorrentInfo, trackers: Vec<Tracker>) -> TorrentFile {
        TorrentFile {
            trackers,
            created_by: CLIENT.into(),
            creation_date: unix_now(),
            info,
        }
    }
}

macro_rules! put_kv {
    ($buf:ident, $key:literal, $value:expr) => {
        $buf.put($key.to_bencode().unwrap().as_slice());
        $buf.put($value.to_bencode().unwrap().as_slice());
    };
}

impl From<TorrentFile> for Bytes {
    fn from(torrent: TorrentFile) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(b'd');
        if !torrent.trackers.is_empty() {
            put_kv!(
                buf,
                "announce-list",
                torrent
                    .trackers
                    .into_iter()
                    .map(|tr| vec![tr.url_str().to_string()])
                    .collect::<Vec<Vec<String>>>()
            );
        }
        put_kv!(buf, "created by", torrent.created_by);
        put_kv!(buf, "creation date", torrent.creation_date);
        buf.put("info".to_bencode().unwrap().as_slice());
        buf.put(Bytes::from(torrent.info));
        buf.put_u8(b'e');
        buf.freeze()
    }
}

fn check_bencode_dict(buf: &Bytes) -> Result<(), BencodeDictError> {
    let mut decoder = Decoder::new(buf);
    match decoder.next_object() {
        Ok(Some(Object::Dict(mut dd))) => {
            if dd.consume_all().is_err() {
                return Err(BencodeDictError::Syntax);
            }
        }
        Ok(Some(_)) => return Err(BencodeDictError::NotADict),
        Ok(None) => return Err(BencodeDictError::Empty),
        Err(_) => return Err(BencodeDictError::Syntax),
    }
    if !matches!(decoder.next_object(), Ok(None)) {
        return Err(BencodeDictError::Trailing);
    }
    Ok(())
}

fn unix_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_secs())
            .map(|i| -i)
            .unwrap_or(i64::MIN),
    }
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum ConstructError {
    #[error("metadata size of {0} exceeds {} limit", MAX_INFO_LENGTH)]
    TooLarge(u32),
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum PushError {
    #[error("too many metadata pieces fetched")]
    TooManyPieces,
    #[error("wrong length for metadata piece {index}: expected {expected}, got {got}")]
    Length {
        index: usize,
        expected: usize,
        got: usize,
    },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum BuildError {
    #[error(transparent)]
    Bencode(#[from] BencodeDictError),
    #[error("not all metadata pieces fetched; {left} remaining")]
    NotFinished { left: usize },
    #[error("info hash mismatch: expected {expected}, got {got:x}")]
    Digest { expected: InfoHash, got: Bytes },
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum BencodeDictError {
    #[error("data is not valid bencode")]
    Syntax,
    #[error("data is not a bencode dict")]
    NotADict,
    #[error("data is empty")]
    Empty,
    #[error("data has trailing bytes after bencode dict")]
    Trailing,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;

    #[test]
    fn test_check_good_bencode_dict() {
        let buf = Bytes::from(b"d3:foo3:bar3:keyi42ee".as_slice());
        assert_eq!(check_bencode_dict(&buf), Ok(()));
    }

    #[test]
    fn test_check_invalid_bencode() {
        let buf = Bytes::from(b"d3:keyi42e8:no valuee".as_slice());
        assert_eq!(check_bencode_dict(&buf), Err(BencodeDictError::Syntax));
    }

    #[test]
    fn test_check_bencode_non_dict() {
        let buf = Bytes::from(b"l3:keyi42e8:no valuee".as_slice());
        assert_eq!(check_bencode_dict(&buf), Err(BencodeDictError::NotADict));
    }

    #[test]
    fn test_check_empty_bencode() {
        let buf = Bytes::new();
        assert_eq!(check_bencode_dict(&buf), Err(BencodeDictError::Empty));
    }

    #[test]
    fn test_check_trailing_bencode() {
        let buf = Bytes::from(b"d3:foo3:bar3:keyi42ee5:extra".as_slice());
        assert_eq!(check_bencode_dict(&buf), Err(BencodeDictError::Trailing));
    }

    #[test]
    fn test_torrent_info_builder() {
        let metadata_size = 40 << 10;
        let info_hash = "fd33560457eae4b165bc5e7f7de6f24db61e957e"
            .parse::<InfoHash>()
            .unwrap();
        let mut builder = TorrentInfoBuilder::new(info_hash, metadata_size).unwrap();
        assert_eq!(builder.next_piece(), Some(0));
        let mut piece0 = BytesMut::with_capacity(16 << 10);
        piece0.put(b"d4:name15:My Test Torrent11:xtra-filler40914:".as_slice());
        piece0.put_bytes(0, 16339);
        builder.push(piece0.freeze()).unwrap();
        assert_eq!(builder.next_piece(), Some(1));
        builder.push(BytesMut::zeroed(16 << 10).freeze()).unwrap();
        assert_eq!(builder.next_piece(), Some(2));
        let mut piece2 = BytesMut::with_capacity(8 << 10);
        piece2.put_bytes(0, (8 << 10) - 1);
        piece2.put_u8(b'e');
        builder.push(piece2.freeze()).unwrap();
        assert_eq!(builder.next_piece(), None);
        let info = builder.build().unwrap();
        assert_eq!(info.name(), Some(Cow::from("My Test Torrent")));
    }

    #[test]
    fn test_torrent_file_into_bytes() {
        let info = TorrentInfo {
            info_hash: "ddbf90f0d41c8f91a555192279845bc45e530ec9".parse::<InfoHash>().unwrap(),
            data: Bytes::from(b"d6:lengthi42e4:name8:blob.dat12:piece lengthi65535e6:pieces20:00000000000000000000e".as_slice()),
        };
        let torrent = TorrentFile {
            info,
            trackers: vec![
                "http://tracker.example.com:8080/announce"
                    .parse::<Tracker>()
                    .unwrap(),
                "udp://bits.example.net:9001".parse::<Tracker>().unwrap(),
            ],
            creation_date: 1686939764,
            created_by: "demagnetize vDEV".into(),
        };
        let buf = Bytes::from(torrent);
        assert_eq!(buf, b"d13:announce-listll40:http://tracker.example.com:8080/announceel27:udp://bits.example.net:9001ee10:created by16:demagnetize vDEV13:creation datei1686939764e4:infod6:lengthi42e4:name8:blob.dat12:piece lengthi65535e6:pieces20:00000000000000000000ee".as_slice());
        check_bencode_dict(&buf).unwrap();
    }
}
