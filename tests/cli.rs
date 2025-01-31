#![cfg(test)]
use assert_cmd::Command;
use bendy::decoding::FromBencode;
use bendy::encoding::ToBencode;
use bendy::value::Value;
use bytes::Bytes;
use sha1::{Digest, Sha1};
use tempfile::tempdir;

fn test_get(magnet: &str, hash: &str, trackers: &[&str]) {
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
    let path = tmp_path.path().join(format!("{hash}.torrent"));
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
    assert_eq!(format!("{digest:x}"), hash);
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
    let mut announced = Vec::new();
    for vals in lst {
        let Value::List(sublist) = vals else {
            panic!("Element of announce-list is not a list");
        };
        let Value::Bytes(bs) = sublist.into_iter().next().unwrap() else {
            panic!("Element of element of announce-list is not a string");
        };
        let tr = String::from_utf8(bs.into_owned()).unwrap();
        announced.push(tr);
    }
    assert_eq!(announced, trackers);
    assert!(d.is_empty());
}

#[test]
fn get_magnet_udp_trackers() {
    test_get(
        concat!(
            "magnet:?xt=urn:btih:63a04291a8b266d968aa7ab8a276543fa63a9e84",
            "&dn=libgen-rs-r_000",
            "&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337%2Fannounce",
            "&tr=udp%3A%2F%2Fexodus.desync.com%3A6969%2Fannounce",
            "&tr=udp%3A%2F%2Fipv4.tracker.harry.lu%3A80%2Fannounce",
            "&tr=udp%3A%2F%2Fopen.stealth.si%3A80%2Fannounce",
            "&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce",
        ),
        "63a04291a8b266d968aa7ab8a276543fa63a9e84",
        [
            "udp://tracker.opentrackr.org:1337/announce",
            "udp://exodus.desync.com:6969/announce",
            "udp://ipv4.tracker.harry.lu:80/announce",
            "udp://open.stealth.si:80/announce",
            "udp://tracker.coppersurfer.tk:6969/announce",
        ]
        .as_slice(),
    );
}

#[test]
fn get_magnet_http_trackers_multipiece_info() {
    test_get(
        concat!(
            "magnet:?xt=urn:btih:b851474b74f65cd19f981c723590e3e520242b97",
            "&dn=debian-12.0.0-amd64-netinst.iso",
            "&tr=http%3A%2F%2Fbttracker.debian.org%3A6969%2Fannounce",
            "&ws=https%3A%2F%2Fcdimage.debian.org%2Fcdimage%2Frelease%2F12.0.0%2Famd64%2Fiso-cd%2Fdebian-12.0.0-amd64-netinst.iso",
            "&ws=https%3A%2F%2Fcdimage.debian.org%2Fcdimage%2Farchive%2F12.0.0%2Famd64%2Fiso-cd%2Fdebian-12.0.0-amd64-netinst.iso",
        ),
        "b851474b74f65cd19f981c723590e3e520242b97",
        ["http://bttracker.debian.org:6969/announce"].as_slice(),
    );
}
