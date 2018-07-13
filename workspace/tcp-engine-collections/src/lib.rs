// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2018 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#![allow(non_upper_case_globals)]
#![deny(missing_docs)]
#![feature(allocator_api)]
#![feature(const_fn)]
#![feature(core_intrinsics)]
#![feature(untagged_unions)]


//! # tcp-engine-collections
//!


extern crate dpdk_unix;
extern crate libc;
//extern crate num_traits;
#[macro_use] extern crate tcp_engine_likely;
extern crate tcp_engine_time;


/// An efficient arena allocator.
pub mod arena_allocation;


/// Least Recently Used caches.
pub mod least_recently_used_cache;


/// Magic ring buffers.
pub mod magic_ring_buffer;


use ::dpdk_unix::page_size;
use ::dpdk_unix::android_linux::page_table::HasVirtualAddress;
use ::dpdk_unix::memory_information::PhysicalAddress;
use ::dpdk_unix::memory_information::VirtualAddress;
use ::libc::c_void;
use ::libc::close;
use ::libc::ftruncate;
use ::libc::mkstemps;
use ::libc::mlock;
use ::libc::mmap;
use ::libc::PROT_NONE;
use ::libc::PROT_READ;
use ::libc::PROT_WRITE;
use ::libc::MAP_ANONYMOUS;
use ::libc::MAP_FAILED;
use ::libc::MAP_FIXED;
use ::libc::MAP_NORESERVE;
use ::libc::MAP_PRIVATE;
use ::libc::MAP_SHARED;
use ::libc::munmap;
use ::libc::unlink;
use ::std::cell::RefCell;
use ::std::collections::HashMap;
use ::std::cmp::Eq;
use ::std::ffi::CString;
use ::std::fmt;
use ::std::fmt::Debug;
use ::std::fmt::Display;
use ::std::fmt::Formatter;
use ::std::hash::Hash;
use ::std::hash::Hasher;
use ::std::io;
use ::std::mem::align_of;
use ::std::mem::ManuallyDrop;
use ::std::mem::size_of;
use ::std::ops::Add;
use ::std::ops::AddAssign;
use ::std::ops::Mul;
use ::std::ops::Sub;
use ::std::ops::SubAssign;
#[allow(unused_imports)] use ::std::os::unix::ffi::OsStrExt;
use ::std::path::Path;
use ::std::ptr::NonNull;
use ::std::ptr::null_mut;
use ::std::rc::Rc;
use ::std::slice::from_raw_parts;
use ::std::slice::from_raw_parts_mut;
use ::tcp_engine_time::MillisecondDuration;
use ::tcp_engine_time::MonotonicMillisecondTimestamp;


include!("BoundedHashMap.rs");
