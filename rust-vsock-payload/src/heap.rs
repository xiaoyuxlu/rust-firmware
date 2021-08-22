// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(not(test))]
use linked_list_allocator::LockedHeap;

#[cfg(not(test))]
#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(not(test))]
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

#[cfg(not(test))]
#[alloc_error_handler]
#[allow(clippy::empty_loop)]
fn alloc_error(_info: core::alloc::Layout) -> ! {
    log::info!("alloc_error ... {:?}\n", _info);
    loop {}
}
