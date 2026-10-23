use std::os::unix::thread::JoinHandleExt as _;
use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::AtomicBool;
use std::thread::JoinHandle;

/// The kernel interrupts the request of the thread that receives the signal, so
/// the signal goes to exactly the thread that waits on the mount.
pub fn interrupt<T>(waiting: &JoinHandle<T>) {
    static HANDLER: Once = Once::new();
    HANDLER.call_once(|| {
        // The handler only stops the signal from ending the process.
        let _handler = signal_hook::flag::register(libc::SIGUSR1, Arc::new(AtomicBool::new(false)))
            .expect("the signal gets a handler");
    });
    // SAFETY: Unavoidable: `kill` and `rustix::process::kill_process`, the
    // safe forms, signal the whole process, and the kernel then interrupts
    // whichever thread takes the signal. The thread is neither joined nor
    // detached while `waiting` is borrowed, so the handle names a thread that
    // exists.
    let sent = unsafe { libc::pthread_kill(waiting.as_pthread_t(), libc::SIGUSR1) };
    assert_eq!(sent, 0, "the signal is sent");
}
