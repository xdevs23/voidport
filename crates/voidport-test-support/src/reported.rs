use voidport_control::{ListenerInfo, VsockPort};
use voidportd::data::Transport;

#[must_use]
pub fn vsock_port(listener: &ListenerInfo) -> u32 {
    assert_eq!(
        listener.transport,
        Transport::Vsock.as_str(),
        "{listener} is not a vsock listener"
    );
    listener
        .endpoint
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or_else(|| panic!("a vsock endpoint is cid:port, not {:?}", listener.endpoint))
}

#[must_use]
pub fn bound_vsock_port(listeners: &[ListenerInfo]) -> u32 {
    let [listener] = listeners else {
        panic!("one listener is reported: {listeners:?}");
    };
    let port = vsock_port(listener);
    assert_ne!(
        VsockPort::from(port),
        VsockPort::Any,
        "the port that was bound is reported"
    );
    port
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidport_control::ANY_CID;
    use voidportd::data::Endpoint;

    #[test]
    fn the_port_a_server_writes_is_the_port_read_back() {
        for cid in [ANY_CID, 3] {
            let written = Endpoint::Vsock { cid, port: 49_152 }.info();
            assert_eq!(vsock_port(&written), 49_152, "{written}");
        }
    }
}
