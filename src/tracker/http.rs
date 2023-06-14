use super::*;
use std::fmt;
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HttpTracker(Url);

impl HttpTracker {
    pub(super) async fn connect(&self) -> Result<HttpTrackerSession<'_>, TrackerError> {
        todo!()
    }
}

impl fmt::Display for HttpTracker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<Tracker {}>", self.0)
    }
}

impl TryFrom<Url> for HttpTracker {
    type Error = TrackerUrlError;

    fn try_from(url: Url) -> Result<HttpTracker, TrackerUrlError> {
        let sch = url.scheme();
        if sch != "http" && sch != "https" {
            return Err(TrackerUrlError::UnsupportedScheme(sch.into()));
        }
        if url.host().is_none() {
            return Err(TrackerUrlError::NoHost);
        }
        Ok(HttpTracker(url))
    }
}

pub(super) struct HttpTrackerSession<'a> {
    pub(super) tracker: &'a HttpTracker,
    // ???
}

impl<'a> HttpTrackerSession<'a> {
    pub(super) async fn announce<'b>(
        &self,
        _announcement: Announcement<'b>,
    ) -> Result<AnnounceResponse, TrackerError> {
        todo!()
    }
}
