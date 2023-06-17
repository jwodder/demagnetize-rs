use assert_cmd::Command;
use bendy::decoding::FromBencode;
use bendy::encoding::ToBencode;
use bendy::value::Value;
use bytes::Bytes;
use sha1::{Digest, Sha1};
use tempfile::tempdir;

#[test]
fn get_magnet() {
    let magnet = concat!(
        "magnet:?xt=urn:btih:fbc325039b4f0e752f2299dca019baadf5095bae",
        "&dn=alpine-standard-3.18.0-aarch64.iso",
        "&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337%2Fannounce",
        "&tr=udp%3A%2F%2Ffosstorrents.com%3A6969%2Fannounce",
        "&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A6969%2Fannounce",
        "&tr=http%3A%2F%2Ftracker.openbittorrent.com%3A80%2Fannounce",
        "&tr=udp%3A%2F%2Ftracker.torrent.eu.org%3A451%2Fannounce",
        "&tr=http%3A%2F%2Ffosstorrents.com%3A6969%2Fannounce",
        "&ws=http%3A%2F%2Fdl-cdn.alpinelinux.org%2Falpine%2Fv3.18%2Freleases%2Faarch64%2Falpine-standard-3.18.0-aarch64.iso",
        "&ws=http%3A%2F%2Fuk.alpinelinux.org%2Falpine%2Fv3.18%2Freleases%2Faarch64%2Falpine-standard-3.18.0-aarch64.iso",
    );
    let tmp_path = tempdir().unwrap();
    Command::cargo_bin("demagnetize")
        .unwrap()
        .arg("--log-level=TRACE")
        .arg("get")
        .arg("-o")
        .arg(tmp_path.path().join("{hash}.torrent"))
        .arg(magnet)
        .assert()
        .success();
    let path = tmp_path
        .path()
        .join("fbc325039b4f0e752f2299dca019baadf5095bae.torrent");
    assert!(path.exists());
    let buf = std::fs::read(path).unwrap();
    let data = Value::from_bencode(&buf).unwrap();
    let Value::Dict(mut d) = data else {
        panic!("Torrent data is not a dict");
    };
    let info = d.remove(b"info".as_slice()).unwrap();
    let Value::Dict(info) = info else {
        panic!("info is not a dict");
    };
    let info_bytes = info.to_bencode().unwrap();
    let digest = Bytes::from(Sha1::digest(info_bytes).to_vec());
    assert_eq!(
        format!("{digest:x}"),
        "fbc325039b4f0e752f2299dca019baadf5095bae"
    );
    let creation_date = d.remove(b"creation date".as_slice()).unwrap();
    assert!(matches!(creation_date, Value::Integer(_)));
    let Value::Bytes(created_by) = d.remove(b"created by".as_slice()).unwrap() else {
        panic!("'created by' is not a string");
    };
    let created_by = std::str::from_utf8(&created_by).unwrap();
    assert!(created_by.starts_with("demagnetize "));
    let announce_list = d.remove(b"announce-list".as_slice()).unwrap();
    let Value::List(lst) = announce_list else {
        panic!("announce-list is not a list");
    };
    let mut trackers = Vec::new();
    for vals in lst {
        let Value::List(sublist) = vals else {
            panic!("Element of announce-list is not a list");
        };
        let Value::Bytes(bs) = sublist.into_iter().next().unwrap() else {
            panic!("Element of element of announce-list is not a string");
        };
        let tr = String::from_utf8(bs.into_owned()).unwrap();
        trackers.push(tr);
    }
    assert_eq!(
        trackers,
        [
            "udp://tracker.opentrackr.org:1337/announce",
            "udp://fosstorrents.com:6969/announce",
            "udp://tracker.openbittorrent.com:6969/announce",
            "http://tracker.openbittorrent.com/announce",
            "udp://tracker.torrent.eu.org:451/announce",
            "http://fosstorrents.com:6969/announce",
        ]
    );
    assert!(d.is_empty());
}
