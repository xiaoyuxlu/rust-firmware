// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::boxed::Box;
use atomic_refcell::AtomicRefCell as RefCell;

use crate::virtio::consts::*;
use crate::virtio::AsBuf;
use crate::virtio::{VirtioError, VirtioTransport};
use crate::virtqueue::VirtQueue;
use crate::vsock::VsockAddr;
use crate::{Error, Result};

use crate::virtio::QUEUE_SIZE;

pub const QUEUE_RX: u16 = 0;
pub const QUEUE_TX: u16 = 1;
pub const QUEUE_EVENT: u16 = 2;

pub const VSOCK_STREAM: u16 = 1;

pub const VSOCK_MTU: u32 = 1500;

#[repr(C)]
#[repr(align(64))]
/// Device driver for virtio block over any transport
pub struct VirtioVsockDevice<'a> {
    transport: Box<dyn VirtioTransport + Send + Sync>,
    rx: RefCell<VirtQueue<'a>>,
    tx: RefCell<VirtQueue<'a>>,
    event: RefCell<VirtQueue<'a>>,
}

impl<'a> VirtioVsockDevice<'a> {
    pub fn new(transport: Box<dyn VirtioTransport + Send + Sync>) -> Result<VirtioVsockDevice<'a>> {
        // Initialise the transport
        let mut transport = transport;
        transport
            .init(VIRTIO_SUBSYSTEM_VSOCK)
            .map_err(Error::VirtioError)?;

        // Reset device
        transport.add_status(64);
        transport.set_status(VIRTIO_STATUS_RESET);

        // Acknowledge
        transport.add_status(VIRTIO_STATUS_ACKNOWLEDGE);

        // And advertise driver
        transport.add_status(VIRTIO_STATUS_DRIVER);

        // And device features ok
        transport.add_status(VIRTIO_STATUS_FEATURES_OK);
        if transport.get_status() & VIRTIO_STATUS_FEATURES_OK != VIRTIO_STATUS_FEATURES_OK {
            transport.add_status(VIRTIO_STATUS_FAILED);
            log::info!("VirtioFeatureNegotiationFailed");
            return Err(Error::VirtioError(
                VirtioError::VirtioFeatureNegotiationFailed,
            ));
        }

        // Hardcoded queue size to QUEUE_SIZE at the moment
        let max_queue = transport.get_queue_max_size();
        if max_queue < QUEUE_SIZE as u16 {
            log::info!("max_queue: {}\n", max_queue);
            transport.add_status(VIRTIO_STATUS_FAILED);
            return Err(Error::VirtioError(VirtioError::VirtioQueueTooSmall));
        }
        transport.set_queue_size(QUEUE_SIZE as u16);

        // program queue rx(idx 0)
        let queue_rx = Self::create_queue(transport.as_ref(), QUEUE_RX, QUEUE_SIZE as u16)?;

        // program queues tx(idx 1)
        let queue_tx = Self::create_queue(transport.as_ref(), QUEUE_TX, QUEUE_SIZE as u16)?;

        // program queues event(idx 2)
        let queue_event = Self::create_queue(transport.as_ref(), QUEUE_EVENT, QUEUE_SIZE as u16)?;

        Ok(VirtioVsockDevice {
            transport,
            rx: RefCell::new(queue_rx),
            tx: RefCell::new(queue_tx),
            event: RefCell::new(queue_event),
        })
    }

    pub fn init(&self) -> Result {
        // Report driver ready
        self.transport.add_status(VIRTIO_STATUS_DRIVER_OK);

        if self.transport.get_status() & VIRTIO_STATUS_DRIVER_OK != VIRTIO_STATUS_DRIVER_OK {
            self.transport.add_status(VIRTIO_STATUS_FAILED);
            log::info!("VIRTIO_STATUS_DRIVER_OK failed");
            return Err(Error::VirtioError(
                VirtioError::VirtioFeatureNegotiationFailed,
            ));
        }
        log::info!("VIRTIO_STATUS_DRIVER_OK set\n");

        Ok(())
    }

    // Get current device CID
    pub fn get_cid(&self) -> u64 {
        u64::from(self.transport.read_device_config(0))
            | u64::from(self.transport.read_device_config(4)) << 32
    }

    /// Whether can send packet.
    pub fn can_send(&self) -> bool {
        let tx = self.tx.borrow();
        tx.available_desc() >= 2
    }

    /// Whether can receive packet.
    pub fn can_recv(&self) -> bool {
        let rx = self.rx.borrow();
        rx.can_pop()
    }

    /// Receive a packet.
    pub fn recv(&self, bufs: &[&mut [u8]]) -> Result<usize> {
        let mut rx = self.rx.borrow_mut();
        rx.add(&[], bufs)?;

        while !rx.can_pop() {}

        let (_, len) = rx.pop_used()?;
        Ok(len as usize)
    }

    /// Send a packet
    pub fn send(&self, bufs: &[&[u8]]) -> Result<usize> {
        let mut tx = self.tx.borrow_mut();

        tx.add(bufs, &[])?;

        self.transport.set_queue(QUEUE_TX);
        self.transport.notify_queue(QUEUE_TX);

        while !tx.can_pop() {}

        let (_, len) = tx.pop_used()?;

        Ok(len as usize)
        // Ok(0)
    }

    /// test a packet.
    pub fn test_server(&self) {
        log::info!("start listen 33:1234\n");
        let mut packet_header = VirtioVsockHdr::default();
        let len = self
            .recv(&[packet_header.as_buf_mut()])
            .expect("recv op request error");

        assert_eq!(len, core::mem::size_of::<VirtioVsockHdr>());
        log::info!("packat_header: {:?}\n", packet_header);
        if packet_header.op != VIRTIO_VSOCK_OP_REQUEST {
            return;
        }

        // send back connect response
        let responder_header = packet_header.generate_responder_header();
        let len = self
            .send(&[responder_header.as_buf()])
            .expect("send op response error");
        assert_eq!(len, core::mem::size_of::<VirtioVsockHdr>());

        loop {
            log::info!("connected loop\n");
            let mut package_header = VirtioVsockHdr::default();
            let mut recv_buf = [0u8; 1500];
            let res = self
                .recv(&[package_header.as_buf_mut(), &mut recv_buf[..]])
                .expect("recv l1 error");
            log::info!("recv l1: header: {:?}\n", package_header);
            let total = package_header.get_len() as usize;
            // let res = self.recv(&mut recv_buf[0..total]).expect("recv l2 error");
            // log::info!("recv l2: buf: {:#x?}\n", &recv_buf[0..total]);
            assert_eq!(res, total + core::mem::size_of::<VirtioVsockHdr>());
            for b in &recv_buf[0usize..total] {
                rust_ipl_log::write_args(format_args!("{}", char::from(*b)))
            }
        }
    }

    pub fn connect(&self, dst_cid: u64, dst_port: u32, src_cid: u64, src_port: u32) -> Result<()> {
        // add recv header buffer
        let mut response_header = VirtioVsockHdr::default();
        let mut rx = self.rx.borrow_mut();
        rx.add(&[], &[response_header.as_buf_mut()])?;

        let request_header = VirtioVsockHdr::create_header(
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            VIRTIO_VSOCK_OP_REQUEST,
            VSOCK_MTU,
        );

        let _res = self.send(&[request_header.as_buf()])?;
        log::info!("connecting after send..\n");
        while !rx.can_pop() {}
        let (_, _len) = rx.pop_used()?;
        log::info!("connecting recved response.. {:?}\n", response_header);

        if response_header.op != VIRTIO_VSOCK_OP_RESPONSE {
            return Err(Error::NotReady);
        }
        let _peer_buf_alloc = response_header.buf_alloc;
        let _peer_fwd_cnt = response_header.fwd_cnt;

        Ok(())
    }
    // test client
    pub fn test_client(&self) {
        log::info!("start connect 2:1234\n");

        let dst_cid = 2;
        let dst_port = 1234;
        let src_cid = self.get_cid();
        let src_port = 40000;

        self.connect(dst_cid, dst_port, src_cid, src_port)
            .expect("connect error");

        let send_data = b"hello, this is from client\n";
        let buf = &send_data[..];

        let package_header = VirtioVsockHdr {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: buf.len() as u32,
            type_: 1,
            op: VIRTIO_VSOCK_OP_RW,
            flags: 0,
            buf_alloc: 262144,
            fwd_cnt: 0,
        };

        self.send(&[package_header.as_buf(), buf])
            .expect("send failed");
        log::info!("sended");

        let mut recv_buf = [0u8; 1500];
        let mut package_header = VirtioVsockHdr::default();
        self.recv(&[package_header.as_buf_mut(), &mut recv_buf[..]])
            .expect("recv error");
        for b in &recv_buf[0usize..package_header.get_len() as usize] {
            rust_ipl_log::write_args(format_args!("{}", char::from(*b)))
        }
    }

    fn create_queue(
        transport: &dyn VirtioTransport,
        idx: u16,
        queue_size: u16,
    ) -> Result<VirtQueue<'a>> {
        transport.set_queue(idx);
        transport.set_queue_size(queue_size);
        let queue = VirtQueue::new(transport, idx as usize, queue_size)?;
        transport.set_queue_enable();
        Ok(queue)
    }
}

/* Connect operations */
pub const VIRTIO_VSOCK_OP_REQUEST: u16 = 1u16;
pub const VIRTIO_VSOCK_OP_RESPONSE: u16 = 2;
#[allow(dead_code)]
pub const VIRTIO_VSOCK_OP_RST: u16 = 3;
#[allow(dead_code)]
pub const VIRTIO_VSOCK_OP_SHUTDOWN: u16 = 4;
/* To send payload */
pub const VIRTIO_VSOCK_OP_RW: u16 = 5;
/* Tell the peer our credit info */
#[allow(dead_code)]
pub const VIRTIO_VSOCK_OP_CREDIT_UPDATE: u16 = 6;
/* Request the peer to send the credit info to us */
#[allow(dead_code)]
pub const VIRTIO_VSOCK_OP_CREDIT_REQUEST: u16 = 7;

// The vsock packet header
// virtio_vsock_hdr
// REF: https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/virtio-v1.1-cs01.html#x1-3960006
// Packets transmitted or received contain a header before the payload
#[repr(packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtioVsockHdr {
    // Source CID.
    pub src_cid: u64,
    // Destination CID.
    pub dst_cid: u64,
    // Source port.
    pub src_port: u32,
    // Destination port.
    pub dst_port: u32,
    // Data length (in bytes) - may be 0, if there is no data buffer.
    pub len: u32,
    // Socket type. Currently, only connection-oriented streams are defined by the vsock protocol.
    pub type_: u16,
    // Operation ID - one of the VSOCK_OP_* values; e.g.
    pub op: u16,
    // Additional options (flags) associated with the current operation (`op`).
    // Currently, only used with shutdown requests (VSOCK_OP_SHUTDOWN).
    pub flags: u32,
    // Size (in bytes) of the packet sender receive buffer (for the connection to which this packet
    // belongs).
    pub buf_alloc: u32,
    // Number of bytes the sender has received and consumed (for the connection to which this packet
    // belongs). For instance, for our Unix backend, this counter would be the total number of bytes
    // we have successfully written to a backing Unix socket.
    pub fwd_cnt: u32,
}

unsafe impl AsBuf for VirtioVsockHdr {}
impl VirtioVsockHdr {
    pub fn new_example() -> Self {
        VirtioVsockHdr {
            src_cid: 33u64.to_le(),
            dst_cid: 2u64.to_le(),
            src_port: 3292289148u32.to_le(),
            dst_port: 1234u32.to_le(),
            len: 0u32.to_le(),
            type_: 1u16.to_le(),
            op: 1u16.to_le(),
            flags: 0,
            buf_alloc: 1500u32.to_le(),
            fwd_cnt: 0,
        }
    }

    pub fn generate_responder_header(&self) -> VirtioVsockHdr {
        if self.op == VIRTIO_VSOCK_OP_REQUEST {
            VirtioVsockHdr {
                src_cid: self.dst_cid,
                dst_cid: self.src_cid,
                src_port: self.dst_port,
                dst_port: self.src_port,
                len: 0,
                type_: 1,
                op: VIRTIO_VSOCK_OP_RESPONSE,
                flags: 0,
                buf_alloc: VSOCK_MTU,
                fwd_cnt: self.fwd_cnt,
            }
        } else {
            VirtioVsockHdr::default()
        }
    }

    pub fn get_len(&self) -> u32 {
        self.len
    }

    pub fn create_header(
        src_cid: u64,
        dst_cid: u64,
        src_port: u32,
        dst_port: u32,
        op: u16,
        buf_alloc: u32,
    ) -> Self {
        VirtioVsockHdr {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: 0,
            type_: VSOCK_STREAM,
            op,
            flags: 0,
            buf_alloc,
            fwd_cnt: 0,
        }
    }
    pub fn set_len(&mut self, len: u32) {
        self.len = len
    }
    pub fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }
    pub fn src_addr(&self) -> VsockAddr {
        VsockAddr::new(self.src_cid, self.src_port)
    }
    pub fn dst_addr(&self) -> VsockAddr {
        VsockAddr::new(self.dst_cid, self.dst_port)
    }
}
