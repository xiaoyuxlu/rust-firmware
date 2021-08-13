// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use uefi_pi::hob_lib::HobEnums;
use uefi_pi::const_guids::MEMORY_ALLOCATION_HEAP_GUID;

pub fn is_heap_hob(hob: &HobEnums) -> bool {
    match hob {
        HobEnums::MemoryAllocation(memory_allocation) => {
            memory_allocation.alloc_descriptor.name == MEMORY_ALLOCATION_HEAP_GUID
        }
        _ => false,
    }
}
