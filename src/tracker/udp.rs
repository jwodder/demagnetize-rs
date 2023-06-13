use super::*;
use std::fmt;
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UdpTracker(Url);

impl UdpTracker {
    pub(super) async fn connect(&self) -> Result<UdpTrackerSession<'_>, TrackerError> {
        todo!()
    }
}

impl fmt::Display for UdpTracker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<Tracker {}>", self.0)
    }
}

impl TryFrom<Url> for UdpTracker {
    type Error = TrackerUrlError;

    fn try_from(url: Url) -> Result<UdpTracker, TrackerUrlError> {
        let sch = url.scheme();
        if sch != "udp" {
            return Err(TrackerUrlError::UnsupportedScheme(sch.into()));
        }
        if url.host().is_none() {
            return Err(TrackerUrlError::NoHost);
        }
        if url.port().is_none() {
            return Err(TrackerUrlError::NoUdpPort);
        }
        Ok(UdpTracker(url))
    }
}

pub(super) struct UdpTrackerSession<'a> {
    tracker: &'a UdpTracker,
    // ???
}

impl<'a> UdpTrackerSession<'a> {
    pub(super) async fn announce<'b>(
        &self,
        _announcement: Announcement<'b>,
    ) -> Result<AnnounceResponse, TrackerError> {
        todo!()
    }
}
