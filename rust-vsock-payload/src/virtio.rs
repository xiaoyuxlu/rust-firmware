// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub mod consts {

    pub const VIRTIO_SUBSYSTEM_BLOCK: u32 = 2;
    pub const VIRTIO_SUBSYSTEM_VSOCK: u32 = 19;
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
    pub const VIRTIO_STATUS_RESET: u32 = 0;
    pub const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;
    pub const VIRTIO_STATUS_DRIVER: u32 = 2;
    pub const VIRTIO_STATUS_FEATURES_OK: u32 = 8;
    pub const VIRTIO_STATUS_DRIVER_OK: u32 = 4;
    pub const VIRTIO_STATUS_FAILED: u32 = 128;
}

/// Virtio related errors
#[derive(Debug, Eq, PartialEq)]
pub enum VirtioError {
    VirtioUnsupportedDevice,
    VirtioLegacyOnly,
    VirtioFeatureNegotiationFailed,
    VirtioQueueTooSmall,
}

/// Trait to allow separation of transport from block driver
pub trait VirtioTransport {
    fn init(&mut self, device_type: u32) -> Result<(), VirtioError>;
    fn get_status(&self) -> u32;
    fn set_status(&self, status: u32);
    fn add_status(&self, status: u32);
    fn reset(&self);
    fn get_features(&self) -> u64;
    fn set_features(&self, features: u64);
    fn set_queue(&self, queue: u16);
    fn get_queue_max_size(&self) -> u16;
    fn set_queue_size(&self, queue_size: u16);
    fn set_descriptors_address(&self, address: u64);
    fn set_avail_ring(&self, address: u64);
    fn set_used_ring(&self, address: u64);
    fn set_queue_enable(&self);
    fn notify_queue(&self, queue: u16);
    fn read_device_config(&self, offset: u64) -> u32;
}

pub const QUEUE_SIZE: usize = 4;

/// Convert a struct into buffer.
pub unsafe trait AsBuf: Sized {
    fn as_buf(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const _ as _, core::mem::size_of::<Self>()) }
    }
    fn as_buf_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(self as *mut _ as _, core::mem::size_of::<Self>())
        }
    }
}

unsafe impl AsBuf for u32 {}
