/*use crate::libwallet::Error;
use futures::Future;
use futures::Poll;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use tokio::prelude::Async;

pub struct RunningTask {
	task: Option<futures::task::Task>,
}

pub struct RunHandlerInThread {
	// running flag is modifiable from worker thread and Poll.
	running: Arc<AtomicBool>,
	task: Arc<std::sync::Mutex<RunningTask>>,
	// from Poll only,
	task_set: bool,

	// Need option because join require ownership transfer. That is why can't belong to 'self' dicertly
	// (State, Result<Response<Body>>)  - resulting from API call as required by gotham
	worker_thread: Option<thread::JoinHandle<Result<serde_json::Value, Error>>>,
}

impl RunHandlerInThread {
	pub fn new<F>(handler: F) -> RunHandlerInThread
	where
		F: Send + Sync + 'static + FnOnce() -> serde_json::Value,
	{
		// 'self' variables
		let running = Arc::new(AtomicBool::new(true));
		let task = Arc::new(std::sync::Mutex::new(RunningTask { task: None }));

		// thread variables to move
		let thr_task = task.clone();
		let thr_running = running.clone();

		let worker_thread = thread::Builder::new()
			.name("RunHandlerInThread".to_string())
			.spawn(move || {
				let result = handler();
				thr_running.store(false, Ordering::Relaxed);

				let rt = thr_task.lock().unwrap();
				if let Some(ref task) = rt.task {
					task.notify();
				}
				Ok(result)
			})
			.unwrap();

		Self {
			running,
			task,
			task_set: false,
			worker_thread: Some(worker_thread),
		}
	}
}

impl Future for RunHandlerInThread {
	type Item = serde_json::Value;
	type Error = Error;

	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		if !self.task_set {
			// Update current task. at the first polling.
			// Task is needed by thread to notify future executor that job is done
			self.task.lock().unwrap().task = Some(futures::task::current());
			self.task_set = true;
		}

		if self.running.load(Ordering::Relaxed) {
			// We are still running.
			Ok(Async::NotReady)
		} else {
			// The job is done. From the thread we should be able to reprieve the results.
			// Because of all ownership staff we can process this once only.
			// Result Must be OK with Ready or Error.
			// In this case futures executor guarantee call it once and satisfy get tread data once limitation

			// JoinHandle::join required ownership transfer. That is why it can be done once.
			if let Some(thr_info) = self.worker_thread.take() {
				// Gettign results from the task
				let result = thr_info.join().unwrap();
				match result {
					Ok(val) => Ok(Async::Ready(val)),
					Err(err) => Err(err),
				}
			} else {
				// Likely double processing. See comments above.
				panic!("Background thread for REST API died or double processed!");
			}
		}
	}
}
*/
