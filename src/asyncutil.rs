use futures::ready;
use futures::stream::{FuturesUnordered, Stream, StreamExt};
use pin_project_lite::pin_project;
use std::collections::HashSet;
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

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

// TODO: Should there be a limit on the number of tasks running at once?
pub(crate) struct ShutdownGroup {
    handles: FuturesUnordered<JoinHandle<()>>,
    token: CancellationToken,
}

impl ShutdownGroup {
    pub(crate) fn new() -> Self {
        ShutdownGroup {
            handles: FuturesUnordered::new(),
            token: CancellationToken::new(),
        }
    }

    pub(crate) fn spawn<F, Fut>(&self, func: F)
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let future = func(self.token.clone());
        self.handles.push(tokio::spawn(future));
    }

    async fn join(&mut self) {
        while self.handles.next().await.is_some() {}
    }

    pub(crate) async fn shutdown(mut self, duration: Duration) {
        if timeout(duration, self.join()).await.is_err() {
            self.token.cancel();
        }
        self.join().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream::iter;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_unique_stream() {
        let stream = iter([10, 20, 30, 20, 40, 10, 50]).unique();
        assert_eq!(stream.collect::<Vec<_>>().await, vec![10, 20, 30, 40, 50]);
    }

    #[tokio::test]
    async fn test_shutdown_group() {
        let group = ShutdownGroup::new();
        let task1_finished = Arc::new(AtomicBool::new(false));
        let my_finished = task1_finished.clone();
        group.spawn(|token| async move {
            tokio::select! {
                () = token.cancelled() => (),
                () = futures::future::ready(()) => my_finished.store(true, Ordering::Release),
            }
        });
        let task2_cancelled = Arc::new(AtomicBool::new(false));
        let my_cancelled = task2_cancelled.clone();
        group.spawn(|token| async move {
            tokio::select! {
                () = token.cancelled() => my_cancelled.store(true, Ordering::Release),
                () = tokio::time::sleep(Duration::from_secs(10)) => (),
            }
        });
        group.shutdown(Duration::from_secs(1)).await;
        assert!(task1_finished.load(Ordering::Acquire));
        assert!(task2_cancelled.load(Ordering::Acquire));
    }
}
