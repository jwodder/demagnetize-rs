use futures::future::{maybe_done, MaybeDone};
use futures::ready;
use futures::stream::{FuturesUnordered, Stream, StreamExt};
use pin_project_lite::pin_project;
use std::collections::HashSet;
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// `received_stream()` takes a buffer size and an async procedure that takes a
/// [`tokio::sync::mpsc::Sender`], and it returns a stream that runs the
/// procedure to completion while yielding the values passed to the sender.
///
/// If the stream is dropped before completion, the async procedure (which may
/// or may not have completed by that point) is dropped as well.
pub(crate) fn received_stream<F, Fut, T>(buffer: usize, f: F) -> ReceivedStream<Fut, T>
where
    F: FnOnce(Sender<T>) -> Fut,
    Fut: Future<Output = ()>,
{
    let (sender, receiver) = channel(buffer);
    let future = f(sender);
    ReceivedStream {
        future: maybe_done(future),
        receiver: Some(receiver),
    }
}

pin_project! {
    pub(crate) struct ReceivedStream<Fut, T> where Fut: Future {
        #[pin]
        future: MaybeDone<Fut>,
        receiver: Option<Receiver<T>>,
    }
}

impl<Fut, T> Stream for ReceivedStream<Fut, T>
where
    Fut: Future<Output = ()>,
{
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let this = self.project();
        let mut in_progress = this.future.poll(cx).is_pending();
        let recved_all = if let Some(recv) = this.receiver.as_mut() {
            match recv.poll_recv(cx) {
                Poll::Pending => {
                    in_progress = true;
                    false
                }
                Poll::Ready(Some(val)) => return Poll::Ready(Some(val)),
                Poll::Ready(None) => true,
            }
        } else {
            false
        };
        if recved_all {
            *this.receiver = None;
        }
        if in_progress {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }
}

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
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::io::AsyncBufReadExt;

    #[tokio::test]
    async fn test_received_stream() {
        let done = Arc::new(AtomicBool::new(false));
        let inner_done = done.clone();
        let stream = received_stream(5, |sender| async move {
            let cursor = Cursor::new("0 1 2 3 4 5 6 7\n8 9 10\n11 12 13 14\n");
            let mut lines = cursor.lines();
            while let Some(ln) = lines.next_line().await.unwrap() {
                for n in ln
                    .split_ascii_whitespace()
                    .map(|s| s.parse::<usize>().unwrap())
                {
                    if sender.send(n).await.is_err() {
                        return;
                    }
                }
            }
            inner_done.store(true, Ordering::Relaxed);
        })
        .enumerate();
        tokio::pin!(stream);
        while let Some((i, n)) = stream.next().await {
            assert_eq!(i, n);
        }
        assert!(done.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_received_stream_drop() {
        let done = Arc::new(AtomicBool::new(false));
        let inner_done = done.clone();
        let stream = received_stream(5, |sender| async move {
            let cursor = Cursor::new("0 1 2 3 4 5 6 7\n8 9 10\n11 12 13 14\n");
            let mut lines = cursor.lines();
            while let Some(ln) = lines.next_line().await.unwrap() {
                for n in ln
                    .split_ascii_whitespace()
                    .map(|s| s.parse::<usize>().unwrap())
                {
                    if sender.send(n).await.is_err() {
                        return;
                    }
                }
            }
            inner_done.store(true, Ordering::Relaxed);
        });
        tokio::pin!(stream);
        assert_eq!(stream.next().await, Some(0));
        #[allow(clippy::drop_non_drop)]
        drop(stream);
        assert!(!done.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_unique_stream() {
        let stream = iter([10, 20, 30, 20, 40, 10, 50]).unique();
        tokio::pin!(stream);
        assert_eq!(stream.collect::<Vec<_>>().await, vec![10, 20, 30, 40, 50]);
    }

    #[tokio::test]
    async fn test_shutdown_group() {
        let group = ShutdownGroup::new();
        let task1_finished = Arc::new(AtomicBool::new(false));
        let my_finished = task1_finished.clone();
        group.spawn(|token| async move {
            tokio::select! {
                _ = token.cancelled() => (),
                _ = futures::future::ready(()) => my_finished.store(true, Ordering::Release),
            }
        });
        let task2_cancelled = Arc::new(AtomicBool::new(false));
        let my_cancelled = task2_cancelled.clone();
        group.spawn(|token| async move {
            tokio::select! {
                _ = token.cancelled() => my_cancelled.store(true, Ordering::Release),
                _ = tokio::time::sleep(Duration::from_secs(10)) => (),
            }
        });
        group.shutdown(Duration::from_secs(1)).await;
        assert!(task1_finished.load(Ordering::Acquire));
        assert!(task2_cancelled.load(Ordering::Acquire));
    }
}
