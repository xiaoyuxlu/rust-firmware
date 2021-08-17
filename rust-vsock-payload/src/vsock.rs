// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//TBD: remove it
#![allow(unused)]

#[derive(Debug)]
pub struct SocketError;

use crate::virtio::AsBuf;
use crate::virtio_vsock_device::VirtioVsockDevice;
use crate::virtio_vsock_device::VirtioVsockHdr;
use crate::virtio_vsock_device::VIRTIO_VSOCK_OP_RW;
use crate::virtio_vsock_device::VIRTIO_VSOCK_OP_SHUTDOWN;
use crate::vsock_impl;
use crate::vsock_impl::get_vsock_device;
use core::fmt;

pub const RCV_SHUTDOWN: u32 = 1;
pub const SEND_SHUTDOWN: u32 = 2;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct VsockAddr {
    cid: u64,
    port: u32,
}

impl VsockAddr {
    pub fn new(cid: u64, port: u32) -> Self {
        VsockAddr { cid, port }
    }

    pub fn cid(&self) -> u64 {
        self.cid
    }

    pub fn port(&self) -> u32 {
        self.port
    }
}

impl fmt::Display for VsockAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cid: {} port: {}", self.cid(), self.port())
    }
}

impl fmt::Debug for VsockAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub struct VsockListener {}

impl VsockListener {
    /// Create a new VsockListener which is bound and listening on the socket address.
    pub fn bind(addr: &VsockAddr) -> Result<Self, SocketError> {
        Ok(VsockListener {})
    }

    /// Create a new VsockListener with specified cid and port.
    pub fn bind_with_cid_port(cid: u64, port: u32) -> Result<Self, SocketError> {
        Self::bind(&VsockAddr::new(cid, port))
    }

    /// Accept a new incoming connection from this listener.
    pub fn accept(&self) -> Result<(VsockStream, VsockAddr), SocketError> {
        Err(SocketError)
    }
}

impl Drop for VsockListener {
    fn drop(&mut self) {
        todo!("VsockListener drop");
    }
}

pub struct VsockStream {
    dst_addr: VsockAddr,
    src_addr: VsockAddr,
    vsock_device: &'static VirtioVsockDevice<'static>,
}

impl VsockStream {
    /// Open a connection to a remote host.
    /// addr is dst address(cid:port)
    pub fn connect(addr: &VsockAddr) -> Result<Self, SocketError> {
        let vsock_device = vsock_impl::get_vsock_device();

        let src_addr = VsockAddr::new(vsock_device.get_cid(), VsockStream::get_free_port());

        vsock_device
            .connect(addr.cid(), addr.port(), src_addr.cid(), src_addr.port())
            .map_err(|_| SocketError);

        Ok(VsockStream {
            dst_addr: *addr,
            src_addr,
            vsock_device,
        })
    }

    pub fn connect_with_cid_port(cid: u64, port: u32) -> Result<Self, SocketError> {
        Self::connect(&VsockAddr::new(cid, port))
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, SocketError> {
        let mut package_header = VirtioVsockHdr::default();
        let recvn = self
            .vsock_device
            .recv(&[package_header.as_buf_mut(), buf])
            .map_err(|_| SocketError)?;
        if package_header.op != VIRTIO_VSOCK_OP_RW {
            return Err(SocketError);
        }
        Ok(package_header.get_len() as usize)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, SocketError> {
        let mut package_header = VirtioVsockHdr::create_header(
            self.src_addr.cid(),
            self.dst_addr.cid(),
            self.src_addr.port(),
            self.dst_addr.port(),
            VIRTIO_VSOCK_OP_RW,
            1500,
        );

        package_header.set_len(buf.len() as u32);

        if self.vsock_device.can_send() {
            let len = self
                .vsock_device
                .send(&[package_header.as_buf(), buf])
                .map_err(|err| SocketError)?;
            Ok(len)
        } else {
            Err(SocketError)
        }
    }

    fn get_free_port() -> u32 {
        40000
    }

    pub fn shutdown(&mut self) {
        let vsock_device = vsock_impl::get_vsock_device();
        let mut package_header = VirtioVsockHdr::create_header(
            self.src_addr.cid(),
            self.dst_addr.cid(),
            self.src_addr.port(),
            self.dst_addr.port(),
            VIRTIO_VSOCK_OP_SHUTDOWN,
            1500,
        );

        package_header.set_flags(RCV_SHUTDOWN | SEND_SHUTDOWN);

        vsock_device.send(&[package_header.as_buf()]);
    }
}

// impl Read Write Flush for VsockStream

impl Drop for VsockStream {
    fn drop(&mut self) {
        self.shutdown();
    }
}
