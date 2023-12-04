use futures::stream::Stream;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tokio::{sync::Semaphore, task::JoinSet};

/// Like `futures::stream::StreamExt::buffer_unordered()`, but the tasks are
/// spawned on the tokio executor for continuous polling instead of only being
/// polled when the stream is polled
#[derive(Debug)]
pub(crate) struct BufferedTasks<T> {
    tasks: JoinSet<T>,
    semaphore: Arc<Semaphore>,
    closed: bool,
}

impl<T> BufferedTasks<T> {
    pub(crate) fn new(limit: usize) -> Self {
        BufferedTasks {
            tasks: JoinSet::new(),
            semaphore: Arc::new(Semaphore::new(limit)),
            closed: false,
        }
    }

    pub(crate) fn spawn<Fut>(&mut self, fut: Fut)
    where
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let sem = Arc::clone(&self.semaphore);
        self.tasks.spawn(async move {
            let _permit = sem.acquire().await.expect("Semaphore should not be closed");
            fut.await
        });
    }

    pub(crate) fn close(&mut self) {
        self.closed = true;
    }
}

impl<T: 'static> Stream for BufferedTasks<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(self.tasks.poll_join_next(cx)) {
            None if self.closed => None.into(),
            None => Poll::Pending,
            Some(Ok(r)) => Some(r).into(),
            Some(Err(e)) => match e.try_into_panic() {
                Ok(barf) => std::panic::resume_unwind(barf),
                Err(e) => unreachable!(
                    "Task in BufferedTasks should not have been aborted, but got {e:?}"
                ),
            },
        }
    }
}
