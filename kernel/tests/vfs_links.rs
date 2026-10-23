// SPDX-License-Identifier: GPL-2.0

use crate::Result;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NetlinkBuffer, NetlinkHeader,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::link::{
    InfoData, InfoKind, InfoNetkit, LinkAttribute, LinkHeader, LinkInfo, LinkMessage,
};
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::{Socket, SocketAddr};
use std::collections::HashSet;
use std::ffi::CString;
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::os::fd::AsRawFd;

fn create(message: LinkMessage) -> Result {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    let mut request = NetlinkMessage::new(
        header,
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(message)),
    );
    request.finalize();
    let mut bytes = vec![0; request.buffer_len()];
    request.serialize(&mut bytes);

    let socket = Socket::new(NETLINK_ROUTE)?;
    socket.connect(&SocketAddr::new(0, 0))?;
    socket.send(&bytes, 0)?;
    let (reply, _) = socket.recv_from_full()?;
    match NetlinkMessage::<RouteNetlinkMessage>::deserialize(&reply)?.payload {
        NetlinkPayload::Error(confirmation) if confirmation.code.is_none() => Ok(()),
        NetlinkPayload::Error(failure) => {
            Err(format!("creating the link pair failed: {}", failure.to_io()).into())
        }
        other => Err(format!("an unexpected reply to the link request: {other:?}").into()),
    }
}

pub(super) fn link_pair(namespace: &File, name: &str) -> Result<u32> {
    let mut peer = LinkMessage::default();
    peer.attributes
        .push(LinkAttribute::NetNsFd(namespace.as_raw_fd()));
    let mut link = LinkMessage::default();
    link.attributes = vec![
        LinkAttribute::IfName(name.to_owned()),
        LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Netkit),
            LinkInfo::Data(InfoData::Netkit(vec![InfoNetkit::Peer(peer)])),
        ]),
    ];
    create(link)?;
    let name = CString::new(name)?;
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(Error::last_os_error().into()),
        index => Ok(index),
    }
}

pub(super) struct LinkRemovals {
    socket: Socket,
    removed: HashSet<u32>,
}

impl LinkRemovals {
    pub(super) fn subscribe() -> Result<Self> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        socket.add_membership(libc::RTNLGRP_LINK)?;
        Ok(Self {
            socket,
            removed: HashSet::new(),
        })
    }

    fn receive(&mut self, wait: bool) -> Result<bool> {
        self.socket.set_non_blocking(!wait)?;
        let announcement = match self.socket.recv_from_full() {
            Ok((announcement, _)) => announcement,
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let message = NetlinkBuffer::new_checked(&announcement)?;
        if message.message_type() == libc::RTM_DELLINK {
            self.removed
                .insert(LinkHeader::parse(message.payload())?.index);
        }
        Ok(true)
    }

    pub(super) fn removed(&mut self, index: u32) -> Result<bool> {
        while self.receive(false)? {}
        Ok(self.removed.contains(&index))
    }

    pub(super) fn wait_removed(&mut self, index: u32) -> Result {
        while !self.removed.contains(&index) {
            self.receive(true)?;
        }
        Ok(())
    }
}
