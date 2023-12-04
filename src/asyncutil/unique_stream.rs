use futures::ready;
use futures::stream::Stream;
use pin_project_lite::pin_project;
use std::collections::HashSet;
use std::hash::Hash;
use std::pin::Pin;
use std::task::{Context, Poll};

pub(crate) trait UniqueExt: Stream {
    fn unique(self) -> UniqueStream<Self>
    where
        Self: Sized,
        Self::Item: Eq + Hash + Clone,
    {
        UniqueStream::new(self)
    }
}

impl<S: Stream> UniqueExt for S {}

pin_project! {
    #[derive(Clone, Debug)]
    #[must_use = "streams do nothing unless polled"]
    pub(crate) struct UniqueStream<S: Stream> {
        #[pin]
        inner: S,
        seen: HashSet<S::Item>,
    }
}

impl<S: Stream> UniqueStream<S> {
    fn new(inner: S) -> Self
    where
        S::Item: Eq + Hash,
    {
        UniqueStream {
            inner,
            seen: HashSet::new(),
        }
    }
}

impl<S: Stream> Stream for UniqueStream<S>
where
    S::Item: Eq + Hash + Clone,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let mut this = self.project();
        loop {
            match ready!(this.inner.as_mut().poll_next(cx)) {
                Some(value) => {
                    if this.seen.insert(value.clone()) {
                        return Some(value).into();
                    }
                }
                None => return None.into(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream::{iter, StreamExt};

    #[tokio::test]
    async fn test_unique_stream() {
        let stream = iter([10, 20, 30, 20, 40, 10, 50]).unique();
        assert_eq!(stream.collect::<Vec<_>>().await, vec![10, 20, 30, 40, 50]);
    }
}
