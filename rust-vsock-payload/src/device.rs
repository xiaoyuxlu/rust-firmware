// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::boxed::Box;
use conquer_once::spin::OnceCell;

use rust_vsock_payload::virtio_pci::VirtioPciTransport;
use rust_vsock_payload::virtio_vsock_device::VirtioVsockDevice;

pub static VSOCK_DEVICE: OnceCell<VirtioVsockDevice> = OnceCell::uninit();

pub fn init_vsock_device() {
    let vsock_device_id = 2;
    let pci_device = fw_pci::PciDevice::new(0, vsock_device_id, 0);
    let virtio_transport = VirtioPciTransport::new(pci_device);
    let virtio_vsock_device = VirtioVsockDevice::new(Box::new(virtio_transport)).unwrap();
    virtio_vsock_device.init().expect("init vsock device faild");
    VSOCK_DEVICE
        .try_init_once(|| virtio_vsock_device)
        .expect("init vsock device failed\n");
    let cid = VSOCK_DEVICE
        .try_get()
        .expect("get vsock device failed")
        .get_cid();
    log::info!("vsock device init success. cid is {}\n", cid);
}

#[no_mangle]
extern "C" fn get_vsock_device_call() -> u64 {
    return VSOCK_DEVICE.try_get().expect("get vsock device failed") as *const VirtioVsockDevice
        as u64;
}

pub fn get_vsock_device() -> &'static VirtioVsockDevice<'static> {
    unsafe {
        let res = get_vsock_device_call() as *const core::ffi::c_void as *const VirtioVsockDevice;
        &*res
    }
}
