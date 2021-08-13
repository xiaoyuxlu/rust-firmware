// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//TBD: remove it
#![allow(unused)]

#[derive(Debug)]
pub struct SocketError;

use crate::vsock_impl;
use core::fmt;

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
}

impl VsockStream {
    /// Open a connection to a remote host.
    /// addr is dst address(cid:port)
    pub fn connect(addr: &VsockAddr) -> Result<Self, SocketError> {
        let vsock_device = vsock_impl::get_vsock_device();

        let src_addr = VsockAddr::new(vsock_device.get_cid(), VsockStream::get_free_port());
        let dst_addr = addr.clone();

        vsock_device
            .connect(addr.cid(), addr.port(), src_addr.cid(), src_addr.port())
            .map_err(|_| SocketError);

        Err(SocketError)
    }

    pub fn connect_with_cid_port(cid: u64, port: u32) -> Result<Self, SocketError> {
        Self::connect(&VsockAddr::new(cid, port))
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, SocketError> {
        todo!()
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, SocketError> {
        todo!()
    }

    fn get_free_port() -> u32 {
        40000
    }
}

// impl Read Write Flush for VsockStream

impl Drop for VsockStream {
    fn drop(&mut self) {
        todo!("VsockStream drop");
    }
}
