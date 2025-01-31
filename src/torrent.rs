use crate::consts::{CLIENT, MAX_INFO_LENGTH};
use crate::tracker::Tracker;
use crate::types::InfoHash;
use bendy::decoding::{Decoder, Object};
use bendy::encoding::ToBencode;
use bytes::{BufMut, Bytes, BytesMut};
use patharg::OutputArg;
use sha1::{Digest, Sha1};
use std::borrow::Cow;
use std::fmt::Write;
use std::iter::Peekable;
use std::ops::Range;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::fs::create_dir_all;

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
        let mut sizes = vec![Self::PIECE_LENGTH; lgth / Self::PIECE_LENGTH];
        let overflow = lgth % Self::PIECE_LENGTH;
        if overflow > 0 {
            sizes.push(overflow);
        }
        let piece_qty =
            u32::try_from(sizes.len()).expect("number of metadata pieces should fit in a u32");
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
        let index = usize::try_from(index).expect("piece indices should fit in a usize");
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
    trackers: Vec<Arc<Tracker>>,
    creation_date: i64,
    created_by: String,
}

impl TorrentFile {
    pub(crate) fn new(info: TorrentInfo, trackers: Vec<Arc<Tracker>>) -> TorrentFile {
        TorrentFile {
            trackers,
            created_by: CLIENT.into(),
            creation_date: unix_now(),
            info,
        }
    }

    pub(crate) async fn save(self, template: &PathTemplate) -> std::io::Result<()> {
        let name = sanitize(self.info.name().as_deref().unwrap_or("NONAME"));
        let path = OutputArg::from_arg(template.format(&name, self.info.info_hash));
        log::info!(
            "Saving torrent for info hash {} to file {}",
            self.info.info_hash,
            path
        );
        if let Some(parent) = path.path_ref().and_then(|p| p.parent()) {
            if parent != Path::new("") {
                create_dir_all(parent).await?;
            }
        }
        let buf = Bytes::from(self);
        path.async_write(buf).await
    }
}

macro_rules! put_kv {
    ($buf:ident, $key:literal, $value:expr) => {
        $buf.put(
            $key.to_bencode()
                .expect("string keys should be bencodable")
                .as_slice(),
        );
        $buf.put(
            $value
                .to_bencode()
                .expect("torrent file values should be bencodable")
                .as_slice(),
        );
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
                    .map(|tr| vec![tr.url_string()])
                    .collect::<Vec<Vec<String>>>()
            );
        }
        put_kv!(buf, "created by", torrent.created_by);
        put_kv!(buf, "creation date", torrent.creation_date);
        buf.put(
            "info"
                .to_bencode()
                .expect("string should be bencodable")
                .as_slice(),
        );
        buf.put(Bytes::from(torrent.info));
        buf.put_u8(b'e');
        buf.freeze()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PathTemplate(Vec<TemplateElement>);

impl PathTemplate {
    pub(crate) fn format(&self, name: &str, info_hash: InfoHash) -> String {
        let mut buf = String::new();
        for elem in &self.0 {
            match elem {
                TemplateElement::Literal(s) => buf.push_str(s),
                TemplateElement::Name => buf.push_str(name),
                TemplateElement::Hash => {
                    write!(buf, "{info_hash}").expect("fmt::writing to a String should not fail");
                }
            }
        }
        buf
    }
}

impl FromStr for PathTemplate {
    type Err = PathTemplateError;

    fn from_str(s: &str) -> Result<PathTemplate, PathTemplateError> {
        let mut elems = Vec::new();
        let mut buf = String::new();
        let mut brace_iter = s.match_indices('{');
        let mut prev_end = 0;
        while let Some((i, _)) = brace_iter.next() {
            debug_assert!(
                prev_end <= i,
                "prev_end={prev_end:?} was unexpectedly greater than i={i:?}"
            );
            buf.push_str(&s[prev_end..i]);
            match s[i..]
                .char_indices()
                .skip(1)
                .find(|&(_, ch)| !(ch.is_ascii_alphanumeric() || ch == '_'))
            {
                Some((1, '{')) => {
                    buf.push('{');
                    let _ = brace_iter.next();
                    prev_end = i + 2;
                }
                Some((j, '}')) => {
                    if !buf.is_empty() {
                        elems.push(TemplateElement::Literal(buf.replace("}}", "}")));
                        buf.clear();
                    }
                    match &s[(i + 1)..(i + j)] {
                        "name" => elems.push(TemplateElement::Name),
                        "hash" => elems.push(TemplateElement::Hash),
                        field => return Err(PathTemplateError::UnknownField(field.into())),
                    }
                    prev_end = i + j + 1;
                }
                Some(_) => return Err(PathTemplateError::InvalidField(i)),
                None => return Err(PathTemplateError::Unmatched(i)),
            }
        }
        buf.push_str(&s[prev_end..]);
        if !buf.is_empty() {
            elems.push(TemplateElement::Literal(buf.replace("}}", "}")));
        }
        Ok(PathTemplate(elems))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TemplateElement {
    Literal(String),
    Name,
    Hash,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum PathTemplateError {
    #[error("unmatched brace at byte index {0}")]
    Unmatched(usize),
    #[error("malformed placeholder at byte index {0}")]
    InvalidField(usize),
    #[error("unknown placeholder {0:?}")]
    UnknownField(String),
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

fn sanitize(s: &str) -> String {
    static PRINTABLE_UNSANITARY: &str = "/\\<>:|\"?*";
    s.chars()
        .map(|ch| {
            if ch < ' ' || PRINTABLE_UNSANITARY.contains(ch) {
                '_'
            } else {
                ch
            }
        })
        .collect()
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum ConstructError {
    #[error("metadata size of {0} exceeds {max} limit", max = MAX_INFO_LENGTH)]
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
                    .unwrap()
                    .into(),
                "udp://bits.example.net:9001"
                    .parse::<Tracker>()
                    .unwrap()
                    .into(),
            ],
            creation_date: 1686939764,
            created_by: "demagnetize vDEV".into(),
        };
        let buf = Bytes::from(torrent);
        assert_eq!(buf, b"d13:announce-listll40:http://tracker.example.com:8080/announceel27:udp://bits.example.net:9001ee10:created by16:demagnetize vDEV13:creation datei1686939764e4:infod6:lengthi42e4:name8:blob.dat12:piece lengthi65535e6:pieces20:00000000000000000000ee".as_slice());
        check_bencode_dict(&buf).unwrap();
    }

    #[test]
    fn test_path_template() {
        let template = "Torrent-{name}-{hash}.torrent"
            .parse::<PathTemplate>()
            .unwrap();
        let info_hash = "ddbf90f0d41c8f91a555192279845bc45e530ec9"
            .parse::<InfoHash>()
            .unwrap();
        assert_eq!(
            template.format("My Test Torrent", info_hash),
            "Torrent-My Test Torrent-ddbf90f0d41c8f91a555192279845bc45e530ec9.torrent"
        );
    }

    #[test]
    fn test_path_template_escaped_braces() {
        let template = "Torrent-{{{name}}}-{hash}.torrent"
            .parse::<PathTemplate>()
            .unwrap();
        let info_hash = "ddbf90f0d41c8f91a555192279845bc45e530ec9"
            .parse::<InfoHash>()
            .unwrap();
        assert_eq!(
            template.format("My Test Torrent", info_hash),
            "Torrent-{My Test Torrent}-ddbf90f0d41c8f91a555192279845bc45e530ec9.torrent"
        );
    }

    #[test]
    fn test_path_template_no_leading_or_trailing_literals() {
        let template = "{name}-{hash}".parse::<PathTemplate>().unwrap();
        let info_hash = "ddbf90f0d41c8f91a555192279845bc45e530ec9"
            .parse::<InfoHash>()
            .unwrap();
        assert_eq!(
            template.format("My Test Torrent", info_hash),
            "My Test Torrent-ddbf90f0d41c8f91a555192279845bc45e530ec9"
        );
    }

    #[test]
    fn test_path_template_unmatched() {
        let e = "torrent={name".parse::<PathTemplate>().unwrap_err();
        assert_eq!(e, PathTemplateError::Unmatched(8));
        assert_eq!(e.to_string(), "unmatched brace at byte index 8");
    }

    #[test]
    fn test_path_template_nested_field() {
        let e = "{name{hash}torrent}".parse::<PathTemplate>().unwrap_err();
        assert_eq!(e, PathTemplateError::InvalidField(0));
        assert_eq!(e.to_string(), "malformed placeholder at byte index 0");
    }

    #[test]
    fn test_path_template_invalid_field() {
        let e = "torrent={name+hash}".parse::<PathTemplate>().unwrap_err();
        assert_eq!(e, PathTemplateError::InvalidField(8));
        assert_eq!(e.to_string(), "malformed placeholder at byte index 8");
    }

    #[test]
    fn test_path_template_unknown_field() {
        let e = "torrent={tracker}.torrent"
            .parse::<PathTemplate>()
            .unwrap_err();
        assert_eq!(e, PathTemplateError::UnknownField("tracker".into()));
        assert_eq!(e.to_string(), "unknown placeholder \"tracker\"");
    }
}
