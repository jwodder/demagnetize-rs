use futures_util::Stream;
use pin_project_lite::pin_project;
use std::collections::HashSet;
use std::hash::Hash;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

pub(crate) trait UniqueByExt: Stream {
    fn unique_by<F, K>(self, keyfunc: F) -> UniqueByStream<Self, F, K>
    where
        Self: Sized,
        F: Fn(&Self::Item) -> K,
        K: Eq + Hash,
    {
        UniqueByStream::new(self, keyfunc)
    }
}

impl<S: Stream> UniqueByExt for S {}

pin_project! {
    #[derive(Clone, Debug)]
    #[must_use = "streams do nothing unless polled"]
    pub(crate) struct UniqueByStream<S, F, K> {
        #[pin]
        inner: S,
        keyfunc: F,
        seen: HashSet<K>,
    }
}

impl<S, F, K> UniqueByStream<S, F, K> {
    fn new(inner: S, keyfunc: F) -> Self {
        UniqueByStream {
            inner,
            keyfunc,
            seen: HashSet::new(),
        }
    }
}

impl<S, F, K> Stream for UniqueByStream<S, F, K>
where
    S: Stream,
    F: Fn(&S::Item) -> K,
    K: Eq + Hash,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let mut this = self.project();
        loop {
            match ready!(this.inner.as_mut().poll_next(cx)) {
                Some(value) => {
                    if this.seen.insert((this.keyfunc)(&value)) {
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
    use futures_util::stream::{StreamExt, iter};

    #[tokio::test]
    async fn test_unique_by_stream() {
        // 10 = 0b1010 = 2
        // 20 = 0b10100 = 2
        // 30 = 0b11110 = 4
        let stream = iter([4u32, 10, 20, 30, 8]).unique_by(|i| i.count_ones());
        assert_eq!(stream.collect::<Vec<_>>().await, vec![4, 10, 30]);
    }
}
