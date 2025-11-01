#![allow(unused)]
use futures_util::{FutureExt, Stream, future::BoxFuture};
use pin_project_lite::pin_project;
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll, ready};
use tokio::{sync::mpsc, task::JoinSet};

type UnwindResult<T> = Result<T, Box<dyn std::any::Any + Send>>;

/// A handle for executing futures in a task group/nursery that uses a fixed
/// number of worker tasks to await the futures.
///
/// `WorkerNursery` is cloneable and sendable, and so it can be used to spawn
/// futures from inside other tasks in the nursery.  The nursery returned by
/// [`WorkerNursery::new()`] and all clones thereof must be dropped before the
/// corresponding [`WorkerNurseryStream`] can yield `None`.
#[derive(Debug)]
pub(crate) struct WorkerNursery<T> {
    inner: async_channel::Sender<BoxFuture<'static, T>>,
    done: Arc<AtomicBool>,
}

impl<T: Send + 'static> WorkerNursery<T> {
    /// Create a new nursery with `workers` worker tasks and return a handle
    /// for spawning futures and a [`Stream`] of future return values.  `T` is
    /// the `Output` type of the futures that will be spawned in the nursery.
    pub(crate) fn new(workers: NonZeroUsize) -> (WorkerNursery<T>, WorkerNurseryStream<T>) {
        let (input_sender, input_receiver) = async_channel::unbounded::<BoxFuture<'static, T>>();
        let (output_sender, output_receiver) = mpsc::unbounded_channel();
        let mut tasks = JoinSet::new();
        let done = Arc::new(AtomicBool::new(false));
        for _ in 0..workers.get() {
            tasks.spawn({
                let input = input_receiver.clone();
                let output = output_sender.clone();
                let done = done.clone();
                async move {
                    while let Ok(fut) = input.recv().await {
                        if done.load(Ordering::SeqCst) {
                            break;
                        }
                        let r = std::panic::AssertUnwindSafe(fut).catch_unwind().await;
                        if output.send(r).is_err() {
                            break;
                        }
                    }
                }
            });
        }
        (
            WorkerNursery {
                inner: input_sender,
                done: done.clone(),
            },
            WorkerNurseryStream {
                inner: output_receiver,
                closer: Closer(input_receiver),
                done,
                _tasks: tasks,
            },
        )
    }
}

impl<T> WorkerNursery<T> {
    /// Spawn a future that returns `T` in the nursery.  Errors if the nursery
    /// is closed.
    pub(crate) fn spawn<Fut>(&self, fut: Fut) -> Result<(), SpawnError>
    where
        Fut: Future<Output = T> + Send + 'static,
    {
        self.inner.try_send(fut.boxed()).map_err(|_| SpawnError)
    }

    /// Closes the nursery.  Any further calls to [`spawn()`](Self::spawn) will
    /// return an error.
    ///
    /// Returns `true` if this call has closed the nursery and it was not
    /// closed already.
    ///
    /// Any pending futures will still be processed after calling `close()`.
    pub(crate) fn close(&self) -> bool {
        self.inner.close()
    }

    /// Returns `true` if the nursery is closed.
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Calls [`close()`](Self::close) and additionally instructs the workers
    /// to not process any pending futures.  Any futures currently being
    /// processed are still processed to completion.
    ///
    /// Returns `true` if this call has shut down the nursery and it was not
    /// shut down already.
    pub(crate) fn shutdown(&self) -> bool {
        self.close();
        !self.done.swap(true, Ordering::SeqCst)
    }

    /// Returns `true` if the nursery is shut down.
    pub(crate) fn is_shutdown(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    /// Returns `true` if the nursery's input channel is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the number of pending futures in the nursery's input channel.
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }
}

// Clone can't be derived, as that would erroneously add `T: Clone` bounds to
// the impl.
impl<T> Clone for WorkerNursery<T> {
    fn clone(&self) -> WorkerNursery<T> {
        WorkerNursery {
            inner: self.inner.clone(),
            done: self.done.clone(),
        }
    }
}

// pin_project! lets us call poll_recv() in poll_next() without even calling
// project().  Not sure how.
pin_project! {
    /// A [`Stream`] of the values returned by the tasks spawned in a worker
    /// nursery.
    ///
    /// The corresponding [`WorkerNursery`] and all clones thereof must be
    /// dropped before the stream can yield `None`.
    ///
    /// When a `WorkerNurseryStream` is dropped, all tasks in the nursery are
    /// aborted, and the nursery is closed.
    #[derive(Debug)]
    pub(crate) struct WorkerNurseryStream<T> {
        inner: mpsc::UnboundedReceiver<UnwindResult<T>>,
        closer: Closer<T>,
        done: Arc<AtomicBool>,
        _tasks: JoinSet<()>,
    }
}

impl<T: Send> WorkerNurseryStream<T> {
    /// Receives the output from the next input future to complete execution.
    /// Returns `None` if all input futures have been executed and the nursery
    /// is closed.
    ///
    /// # Panics
    ///
    /// If the stream receives a result from a future that panicked, this
    /// method resumes unwinding the panic.
    pub(crate) async fn recv(&mut self) -> Option<T> {
        match self.inner.recv().await? {
            Ok(r) => Some(r),
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    /// Tries to receive the next result for this stream.
    ///
    /// This method returns the [`Empty`] error if the stream is currently
    /// empty but the nursery is still open.
    ///
    /// This method returns the [`Done`] error if the stream is currently empty
    /// and the nursery is closed.
    ///
    /// Unlike the [`poll_recv`] method, this method will never return an
    /// [`Empty`] error spuriously.
    ///
    /// [`Empty`]: crate::TryRecvError::Empty
    /// [`Done`]: crate::TryRecvError::Done
    /// [`poll_recv`]: Self::poll_recv
    ///
    /// # Panics
    ///
    /// If the stream receives a result from a future that panicked, this method
    /// resumes unwinding the panic.
    pub(crate) fn try_recv(&mut self) -> Result<T, TryRecvError> {
        match self.inner.try_recv()? {
            Ok(r) => Ok(r),
            Err(e) => std::panic::resume_unwind(e),
        }
    }
}

impl<T> WorkerNurseryStream<T> {
    /// Closes the nursery.  Any further calls to [`WorkerNursery::spawn()`]
    /// will return an error.
    ///
    /// Returns `true` if this call has closed the nursery and it was not
    /// closed already.
    ///
    /// Any pending futures will still be processed after calling `close()`.
    pub(crate) fn close(&self) -> bool {
        self.closer.close()
    }

    /// Returns `true` if the nursery is closed, meaning either that `close()`
    /// has been called on a [`WorkerNursery`] or the [`WorkerNurseryStream`]
    /// or that all [`WorkerNursery`] stream clones have been dropped.
    pub(crate) fn is_closed(&self) -> bool {
        self.closer.is_closed()
    }

    /// Calls [`close()`](Self::close) and additionally instructs the worker
    /// tasks to not process any pending futures.  Any futures currently being
    /// processed are still processed to completion.
    ///
    /// Returns `true` if this call has shut down the nursery and it was not
    /// shut down already.
    pub(crate) fn shutdown(&self) -> bool {
        self.close();
        !self.done.swap(true, Ordering::SeqCst)
    }

    /// Returns `true` if the nursery is shut down.
    pub(crate) fn is_shutdown(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    /// Returns `true` if the output stream is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the number of pending outputs in the stream.
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }

    /// Polls to receive the next result from this stream.
    ///
    /// This method returns:
    ///
    ///  * `Poll::Pending` if no results are available but the nursery is not
    ///    closed, or if a spurious failure happens.
    ///  * `Poll::Ready(Some(message))` if a result is available.
    ///  * `Poll::Ready(None)` if the nursery has been closed and all results
    ///    have been received.
    ///
    /// # Panics
    ///
    /// If the stream receives a result from a future that panicked, this
    /// method resumes unwinding the panic.
    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        match ready!(self.inner.poll_recv(cx)) {
            Some(Ok(r)) => Some(r).into(),
            Some(Err(e)) => std::panic::resume_unwind(e),
            None => None.into(),
        }
    }
}

impl<T: 'static> Stream for WorkerNurseryStream<T> {
    type Item = T;

    /// Poll for one of the worker tasks to finish processing an input future,
    /// and return the output.
    ///
    /// # Panics
    ///
    /// If the stream receives a result from a future that panicked, this method
    /// resumes unwinding the panic.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.poll_recv(cx)
    }
}

// This type is needed because putting the Drop impl on WorkerNurseryStream
// instead conflicts with pin_project_lite.
#[derive(Debug)]
struct Closer<T>(async_channel::Receiver<BoxFuture<'static, T>>);

impl<T> Closer<T> {
    fn close(&self) -> bool {
        self.0.close()
    }

    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

impl<T> Drop for Closer<T> {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SpawnError;

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "could not spawn future in nursery as it is closed")
    }
}

impl std::error::Error for SpawnError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TryRecvError {
    Empty,
    Done,
}

impl fmt::Display for TryRecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TryRecvError::Empty => write!(f, "nursery output stream is empty"),
            TryRecvError::Done => write!(f, "nursery is done"),
        }
    }
}

impl std::error::Error for TryRecvError {}

impl From<mpsc::error::TryRecvError> for TryRecvError {
    fn from(e: mpsc::error::TryRecvError) -> TryRecvError {
        match e {
            mpsc::error::TryRecvError::Empty => TryRecvError::Empty,
            mpsc::error::TryRecvError::Disconnected => TryRecvError::Done,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use tokio::sync::oneshot;

    #[test]
    fn nursery_is_send() {
        #[allow(dead_code)]
        fn require_send<T: Send>(_t: T) {}

        #[allow(dead_code)]
        fn check_nursery_send<T: Send + 'static>() {
            let (nursery, _) = WorkerNursery::<T>::new(NonZeroUsize::new(42).unwrap());
            require_send(nursery);
        }
    }

    #[tokio::test]
    async fn collect() {
        let (nursery, stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        for i in 0..20 {
            nursery.spawn(std::future::ready(i)).unwrap();
        }
        assert!(!stream.is_closed());
        drop(nursery);
        assert!(stream.is_closed());
        let mut values = stream.collect::<Vec<_>>().await;
        values.sort_unstable();
        assert_eq!(values, (0..20).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn reraise_panic_recv() {
        let (nursery, mut stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        nursery
            .spawn(async { panic!("I can't take this anymore!") })
            .unwrap();
        drop(nursery);
        let r = std::panic::AssertUnwindSafe(stream.recv())
            .catch_unwind()
            .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn reraise_panic_next() {
        let (nursery, mut stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        nursery
            .spawn(async { panic!("I can't take this anymore!") })
            .unwrap();
        drop(nursery);
        let r = std::panic::AssertUnwindSafe(stream.next())
            .catch_unwind()
            .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn close_receiver() {
        let (nursery, stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        for i in 0..5 {
            nursery.spawn(std::future::ready(i)).unwrap();
        }
        assert!(!nursery.is_shutdown());
        assert!(!stream.is_shutdown());
        assert!(!stream.is_closed());
        assert!(!nursery.is_closed());
        assert!(stream.close());
        assert!(nursery.spawn(std::future::ready(5)).is_err());
        assert!(!nursery.is_shutdown());
        assert!(!stream.is_shutdown());
        assert!(stream.is_closed());
        assert!(nursery.is_closed());
        drop(nursery);
        let mut values = stream.collect::<Vec<_>>().await;
        values.sort_unstable();
        assert_eq!(values, (0..5).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn close_sender() {
        let (nursery, stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        for i in 0..5 {
            nursery.spawn(std::future::ready(i)).unwrap();
        }
        assert!(!nursery.is_shutdown());
        assert!(!stream.is_shutdown());
        assert!(!stream.is_closed());
        assert!(!nursery.is_closed());
        assert!(nursery.close());
        assert!(nursery.spawn(std::future::ready(5)).is_err());
        assert!(!nursery.is_shutdown());
        assert!(!stream.is_shutdown());
        assert!(stream.is_closed());
        assert!(nursery.is_closed());
        drop(nursery);
        let mut values = stream.collect::<Vec<_>>().await;
        values.sort_unstable();
        assert_eq!(values, (0..5).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn close_on_shutdown() {
        let (nursery, stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        for i in 0..5 {
            nursery.spawn(std::future::ready(i)).unwrap();
        }
        assert!(!nursery.is_shutdown());
        assert!(!stream.is_shutdown());
        assert!(!stream.is_closed());
        assert!(!nursery.is_closed());
        assert!(stream.shutdown());
        assert!(nursery.spawn(std::future::ready(5)).is_err());
        assert!(nursery.is_shutdown());
        assert!(stream.is_shutdown());
        assert!(stream.is_closed());
        assert!(nursery.is_closed());
        assert!(!nursery.shutdown());
        assert!(!stream.shutdown());
        assert!(nursery.is_shutdown());
        assert!(stream.is_shutdown());
        assert!(stream.is_closed());
        assert!(nursery.is_closed());
        drop(nursery);
        // Note that, because shutdown() prevents queued tasks from running,
        // the stream will nondeterministically return a subset of the
        // incremented inputs.
        assert!(stream.all(|n| async move { (1..6).contains(&n) }).await);
    }

    #[tokio::test]
    async fn dropping_receiver_closes_sender() {
        let (nursery, stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        assert!(!nursery.is_closed());
        drop(stream);
        assert!(nursery.is_closed());
        assert!(nursery.spawn(std::future::ready(5)).is_err());
    }

    #[tokio::test]
    async fn queued_run_after_close() {
        let (nursery, mut stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        let mut txes = Vec::new();
        for _ in 0..10 {
            let (tx, rx) = oneshot::channel();
            nursery.spawn(async move { rx.await.unwrap() }).unwrap();
            txes.push(tx);
        }
        assert_eq!(stream.try_recv(), Err(TryRecvError::Empty));
        nursery.close();
        for (i, tx) in txes.into_iter().enumerate() {
            tx.send(i).unwrap();
        }
        let mut values = stream.collect::<Vec<_>>().await;
        values.sort_unstable();
        assert_eq!(values, (0..10).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn queued_not_run_after_recv_shutdown() {
        let (nursery, mut stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        let mut txes = Vec::new();
        for _ in 0..10 {
            let (tx, rx) = oneshot::channel();
            nursery.spawn(async move { rx.await.unwrap() }).unwrap();
            txes.push(tx);
        }
        // <https://users.rust-lang.org/t/125314>
        tokio::task::yield_now().await;
        assert_eq!(stream.try_recv(), Err(TryRecvError::Empty));
        stream.shutdown();
        for (i, tx) in txes.into_iter().enumerate() {
            let _ = tx.send(i);
        }
        let mut values = stream.collect::<Vec<_>>().await;
        values.sort_unstable();
        assert_eq!(values, (0..5).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn queued_not_run_after_send_shutdown() {
        let (nursery, mut stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        let mut txes = Vec::new();
        for _ in 0..10 {
            let (tx, rx) = oneshot::channel();
            nursery.spawn(async move { rx.await.unwrap() }).unwrap();
            txes.push(tx);
        }
        // <https://users.rust-lang.org/t/125314>
        tokio::task::yield_now().await;
        assert_eq!(stream.try_recv(), Err(TryRecvError::Empty));
        nursery.shutdown();
        for (i, tx) in txes.into_iter().enumerate() {
            let _ = tx.send(i);
        }
        let mut values = stream.collect::<Vec<_>>().await;
        values.sort_unstable();
        assert_eq!(values, (0..5).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn nested_spawn() {
        let (nursery, stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        let inner = nursery.clone();
        nursery
            .spawn(async move {
                inner.spawn(std::future::ready(0)).unwrap();
                std::future::ready(1).await
            })
            .unwrap();
        nursery.spawn(std::future::ready(2)).unwrap();
        nursery.spawn(std::future::ready(3)).unwrap();
        drop(nursery);
        let mut values = stream.collect::<Vec<_>>().await;
        values.sort_unstable();
        assert_eq!(values, vec![0, 1, 2, 3]);
    }

    #[tokio::test]
    async fn no_close_until_drop() {
        let (nursery, mut nursery_stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        nursery.spawn(std::future::ready(1)).unwrap();
        nursery.spawn(std::future::ready(2)).unwrap();
        nursery.spawn(std::future::ready(3)).unwrap();
        let mut values = Vec::new();
        values.push(nursery_stream.next().await.unwrap());
        values.push(nursery_stream.next().await.unwrap());
        values.push(nursery_stream.next().await.unwrap());
        values.sort_unstable();
        assert_eq!(values, vec![1, 2, 3]);
        assert_eq!(nursery_stream.try_recv(), Err(TryRecvError::Empty));
        drop(nursery);
        //assert_eq!(nursery_stream.try_recv(), Err(TryRecvError::Done));
        let r = tokio::time::timeout(std::time::Duration::from_millis(100), nursery_stream.next())
            .await;
        assert_eq!(r, Ok(None));
    }

    #[tokio::test]
    async fn drop_tasks_on_drop_stream() {
        enum Void {}

        let (nursery, nursery_stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        let (sender, receiver) = oneshot::channel::<Void>();
        nursery
            .spawn({
                async move {
                    std::future::pending::<()>().await;
                    drop(sender);
                }
            })
            .unwrap();
        drop(nursery);
        drop(nursery_stream);
        assert!(receiver.await.is_err());
    }

    #[tokio::test]
    async fn nest_nurseries() {
        let (nursery, stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
        nursery
            .spawn(async {
                let (nursery, stream) = WorkerNursery::new(NonZeroUsize::new(5).unwrap());
                nursery.spawn(std::future::ready(1)).unwrap();
                nursery.spawn(std::future::ready(2)).unwrap();
                nursery.spawn(std::future::ready(3)).unwrap();
                drop(nursery);
                stream.fold(0, |accum, i| async move { accum + i }).await
            })
            .unwrap();
        nursery.spawn(std::future::ready(4)).unwrap();
        nursery.spawn(std::future::ready(5)).unwrap();
        drop(nursery);
        let mut values = stream.collect::<Vec<_>>().await;
        values.sort_unstable();
        assert_eq!(values, vec![4, 5, 6]);
    }
}
