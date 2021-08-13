// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use linked_list_allocator::LockedHeap;

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Initialize the heap allocator.
pub(super) fn init(heap_start: usize, heap_size: usize) {
    unsafe {
        HEAP_ALLOCATOR.lock().init(heap_start, heap_size);
    }
    log::info!(
        "Heap allocator init done: {:#x?}\n",
        heap_start..heap_start + heap_size
    );
}

#[alloc_error_handler]
#[allow(clippy::empty_loop)]
fn alloc_error(_info: core::alloc::Layout) -> ! {
    log::info!("alloc_error ... {:?}\n", _info);
    loop {}
}
