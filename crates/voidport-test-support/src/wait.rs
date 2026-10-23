use std::os::fd::AsFd;

use rustix::event::{PollFd, PollFlags, Timespec, poll};

/// Waits until `condition` is true. It describes a state that the sockets cannot
/// report, so it is checked again after every yield. The wait ends with a panic
/// when `ended` reports that nothing can bring the state about any more.
pub fn until(ended: impl Fn() -> bool, mut condition: impl FnMut() -> bool) {
    while !condition() {
        assert!(
            !ended(),
            "the server or program ended before the state the test waits for"
        );
        std::thread::yield_now();
    }
}

#[must_use]
pub fn readable(descriptor: impl AsFd) -> bool {
    let mut events = [PollFd::new(&descriptor, PollFlags::IN)];
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    poll(&mut events, Some(&now)).expect("polling a descriptor") > 0
}
