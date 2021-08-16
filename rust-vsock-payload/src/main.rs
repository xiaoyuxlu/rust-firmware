// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![feature(alloc_error_handler)]

extern crate alloc;
use rust_vsock_payload::virtio::VirtioTransport;
use rust_vsock_payload::virtio_blk_device::VirtioBlockDevice;
use rust_vsock_payload::virtio_pci::VirtioPciTransport;

mod device;
mod heap;
mod hob_utils;
mod mem;

#[no_mangle]
#[cfg_attr(target_os = "uefi", export_name = "efi_main")]
pub extern "win64" fn _start(hob_list: *const u8, _reserved_param: usize) -> ! {
    rust_ipl_log::write_log(
        rust_ipl_log::LOG_LEVEL_INFO,
        rust_ipl_log::LOG_MASK_COMMON,
        format_args!("Enter rust vsock payload\n"),
    );
    rust_ipl_log::init_with_level(log::Level::Trace);
    log::debug!("Logger init\n");

    let hob_list = unsafe_get_hob_from_ipl(hob_list);
    uefi_pi::hob_lib::dump_hob(hob_list);

    let hob = uefi_pi::hob_lib::HobList::new(hob_list)
        .find(|hob| -> bool { hob_utils::is_heap_hob(hob) })
        .unwrap();
    // half memory allocation for heap, and half for DMA
    if let uefi_pi::hob_lib::HobEnums::MemoryAllocation(memory_allocation) = hob {
        let half_size = (memory_allocation.alloc_descriptor.memory_length / 2) as usize;
        let memory_base_address = memory_allocation.alloc_descriptor.memory_base_address;
        heap::init(memory_base_address as usize, half_size as usize);
        rust_vsock_payload::virtio_impl_init(
            memory_base_address as usize + half_size,
            half_size as usize,
        );
    }

    fw_pci::print_bus();
    init_platform();
    // test_block_device();
    device::init_vsock_device();
    test_vsock_device();
    // dump_pcis();

    loop {}
}

#[cfg(target_os = "uefi")]
use core::panic::PanicInfo;

use rust_vsock_payload::virtio_blk_device::SectorRead;

#[cfg(target_os = "uefi")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    rust_ipl_log::write_log(
        rust_ipl_log::LOG_LEVEL_ERROR,
        rust_ipl_log::LOG_MASK_COMMON,
        format_args!("panic ... {:?}\n", _info),
    );
    // log::trace!("panic ... {:?}\n", _info);
    loop {}
}

fn unsafe_get_hob_from_ipl<'a>(hob: *const u8) -> &'a [u8] {
    const SIZE_4M: usize = 0x40_0000;
    let hob = unsafe { core::slice::from_raw_parts(hob as *const u8, SIZE_4M) };
    let hob_size = uefi_pi::hob_lib::get_hob_total_size(hob).expect("Get hob size failed");
    &hob[..hob_size] as _
}

fn dump_bar(offset: u8, pci_devide: &fw_pci::PciDevice) {
    let bar0 = pci_devide.read_u32(offset);
    rust_ipl_log::write_args(format_args!(
        "bar offset {:X}, value: {:#08x}\n",
        offset, bar0
    ));
}

fn dump_pci(pci_device: &fw_pci::PciDevice) {
    log::info!(
        "pci: {:02X}:{:02X}:{:02X}\n",
        pci_device.bus,
        pci_device.device,
        pci_device.func
    );

    let command = pci_device.read_u16(0x4);
    let status = pci_device.read_u16(0x6);
    rust_ipl_log::write_args(format_args!(
        "bit  \t fedcba9876543210\nstate\t {:016b}\ncommand\t {:016b}\n",
        status, command
    ));
    dump_bar(0x10, pci_device);
    dump_bar(0x14, pci_device);
    dump_bar(0x18, pci_device);
    dump_bar(0x1C, pci_device);
    dump_bar(0x20, pci_device);
    dump_bar(0x24, pci_device);

    dump_pic_16_bytes(0x0, pci_device);
    dump_pic_16_bytes(0x10, pci_device);
    dump_pic_16_bytes(0x20, pci_device);
    dump_pic_16_bytes(0x30, pci_device);
}

fn dump_pic_16_bytes(offset: u8, pci_device: &fw_pci::PciDevice) {
    rust_ipl_log::write_args(format_args!("{:02x}:", offset));
    for i in 0..16 {
        let res0 = pci_device.read_u8(offset + i);
        rust_ipl_log::write_args(format_args!(" {:02x}", res0));
    }
    rust_ipl_log::write_args(format_args!("\n"));
}

fn init_platform() {
    // let pci_device = fw_pci::PciDevice::new(0, 0, 0);
    // pci_device.write_u16(0x4, 0x7);
    // pci_device.write_u8(0x3C, 0xff);
    // let pciexbar = pci_device.read_u64(0x60);
    // log::info!("pci 00:00.0.0x60, {:02x?}\n", pciexbar.to_le_bytes());

    // let pci_device = fw_pci::PciDevice::new(0, 0x1f, 0);
    // pci_device.write_u16(0x4, 0x7);
    // pci_device.write_u8(0x3C, 0xff);

    // let pci_device = fw_pci::PciDevice::new(0, 0x1f, 2);
    // pci_device.write_u16(0x4, 0x0407);
    // pci_device.write_u8(0x20, 0xC1);
    // pci_device.write_u8(0x21, 0x60);
    // pci_device.write_u8(0x27, 0xC0);
    // pci_device.write_u8(0x3C, 0x0A);
    // // pci_device.write_u8(0x3C, 0xff);

    // let pci_device = fw_pci::PciDevice::new(0, 0x1f, 3);
    // pci_device.write_u8(0x4, 0x07);
    // pci_device.write_u8(0x20, 0x81);
    // pci_device.write_u8(0x21, 0x60);
    // pci_device.write_u8(0x28, 0xC0);
    // pci_device.write_u8(0x3C, 0x0A);
    // // pci_device.write_u16(0x20, 0x60c1);
    // // pci_device.write_u32(0x24, 0xc0000000);

    // // block device init
    // let pci_device = fw_pci::PciDevice::new(0, 1, 0);
    // pci_device.write_u8(0x4, 0x7);
    // pci_device.write_u8(0x5, 0x4);
    // pci_device.write_u8(0x11, 0x60);
    // pci_device.write_u8(0x15, 0x10);
    // pci_device.write_u8(0x17, 0xc0);
    // pci_device.write_u32(0x20, 0xfe000008);
    // pci_device.write_u32(0x24, 0);
    // pci_device.write_u8(0x3C, 0x0a);

    // vsock device init
    let pci_device = fw_pci::PciDevice::new(0, 2, 0);
    pci_device.write_u8(0x4, 0x7);
    pci_device.write_u8(0x5, 0x4);
    pci_device.write_u8(0x10, 0xe1);
    pci_device.write_u8(0x11, 0x60);
    pci_device.write_u8(0x15, 0x20);
    pci_device.write_u8(0x17, 0xc0);
    pci_device.write_u32(0x20, 0xfe000008);
    pci_device.write_u32(0x24, 0);
    pci_device.write_u8(0x3C, 0x0a);

    dump_pci(&pci_device);
}

fn _test_block_device() {
    let pci_device = fw_pci::PciDevice::new(0, 1, 0);
    let mut virtio_transport = VirtioPciTransport::new(pci_device);
    virtio_transport.init(0x2).unwrap();
    let pci_device = fw_pci::PciDevice::new(0, 1, 0);
    dump_pci(&pci_device);

    let virtio_blk_device = VirtioBlockDevice::new(&mut virtio_transport).expect("init error");
    virtio_blk_device.init().unwrap();
    let capacity = virtio_blk_device.get_capacity();
    log::info!("block device capacity: {}\n", capacity);

    let mut data = [0u8; 512];
    virtio_blk_device.read(1, &mut data[..]).unwrap();
    log::info!("block 1: {:02x?}\n", &data[0..16]);
}

fn test_vsock_device() {
    let vsock_device = device::get_vsock_device();
    let cid = vsock_device.get_cid();
    log::info!("virtio_vsock_device cid is {}\n", cid);

    use rust_vsock_payload::vsock::{VsockAddr, VsockStream};

    let mut stream = VsockStream::connect(&VsockAddr::new(2, 1234)).expect("connect error");
    stream.write(b"This is from client").expect("write error");

    log::info!("virtio_vsock_device test done\n");
}
