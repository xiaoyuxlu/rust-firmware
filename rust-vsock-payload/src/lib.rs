#![cfg_attr(not(test), no_std)]

extern crate alloc;
use core::mem::size_of;

const PAGE_SIZE: usize = 0x1000;

mod hal;
mod mem;
pub mod virtio;
pub mod virtio_blk_device;
mod virtio_impl;
pub mod virtio_pci;
pub mod virtio_vsock_device;
pub mod virtqueue;
pub use hal::*;
pub mod ring_buffer;
pub mod vsock;
pub mod vsock_impl;

pub use virtio_impl::init as virtio_impl_init;

/// The type returned by driver methods.
pub type Result<T = ()> = core::result::Result<T, Error>;

// pub struct Error {
//     kind: ErrorKind,
//     reason: &'static str,
// }

/// The error type of VirtIO drivers.
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// The buffer is too small.
    BufferTooSmall,
    /// The device is not ready.
    NotReady,
    /// The queue is already in use.
    AlreadyUsed,
    /// Invalid parameter.
    InvalidParam,
    /// Failed to alloc DMA memory.
    DmaError,
    /// I/O Error
    IoError,
    /// Devide Error
    VirtioError(virtio::VirtioError),
    /// No packet Error
    PacketNotReady,
    /// An operation cannot proceed because a buffer is empty or full.
    Exhausted,
    /// An incoming packet could not be recognized and was dropped.
    /// E.g. an Ethernet packet with an unknown EtherType.
    Unrecognized,
    /// An incoming packet could not be parsed because some of its fields were out of bounds
    /// of the received data.
    Truncated,
}

/// Align `size` up to a page.
fn align_up(size: usize) -> usize {
    (size + PAGE_SIZE) & !(PAGE_SIZE - 1)
}

/// Pages of `size`.
#[allow(dead_code)]
fn pages(size: usize) -> usize {
    (size + PAGE_SIZE - 1) / PAGE_SIZE
}

/// Convert a struct into buffer.
unsafe trait AsBuf: Sized {
    fn as_buf(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const _ as _, size_of::<Self>()) }
    }
    fn as_buf_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self as *mut _ as _, size_of::<Self>()) }
    }
}

#[cfg(test)]
mod test;
