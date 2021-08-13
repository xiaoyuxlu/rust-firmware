// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::virtio_vsock_device::VirtioVsockDevice;

extern "C" {
    fn get_vsock_device_call() -> u64;
}

pub fn get_vsock_device() -> &'static VirtioVsockDevice<'static> {
    unsafe {
        let res = get_vsock_device_call() as *const core::ffi::c_void as *const VirtioVsockDevice;
        &*res
    }
}
