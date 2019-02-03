// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2018 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![deny(missing_docs)]
#![feature(asm)]
#![feature(const_fn)]
#![feature(core_intrinsics)]
#![feature(int_to_from_bytes)]
#![feature(untagged_unions)]


//! # tcp-engine
//!


#[cfg(feature = "dpdk-sys")] extern crate dpdk_sys;
extern crate hashbrown;
extern crate libc;
#[macro_use] extern crate likely;
#[macro_use] extern crate memoffset;
extern crate network_check_sum;
extern crate network_collections;
extern crate network_endian;
extern crate network_time;
extern crate tcp_engine_internet_protocol;
extern crate tcp_engine_ports;
extern crate tcp_engine_tcp_domain;


use self::api::*;
#[macro_use] use self::api::tcp::*;


/// API.
pub mod api;


/// Transmission Control Protocol (TCP).
pub mod tcp;


use ::arrayvec::ArrayVec;
use ::dpdk_unix::page_size;
use ::hashbrown::HashMap;
use ::hyper_thread_random::generate_hyper_thread_safe_random_u16;
use ::hyper_thread_random::generate_hyper_thread_safe_random_u32;
use ::hyper_thread_random::generate_hyper_thread_safe_random_u64;
#[cfg(feature = "dpdk-sys")] use ::dpdk_sys::*;
use ::libc::c_void;
use ::libc::close;
use ::libc::ftruncate;
use ::libc::mkstemps;
use ::libc::mlock;
use ::libc::mmap;
use ::libc::PROT_READ;
use ::libc::PROT_WRITE;
use ::libc::MAP_ANONYMOUS;
use ::libc::MAP_FAILED;
use ::libc::MAP_NORESERVE;
use ::libc::MAP_PRIVATE;
use ::libc::MAP_SHARED;
use ::libc::munmap;
use ::libc::unlink;
use ::md5::Digest as Md5Digest;
use ::md5::Md5;
use ::std::cell::Cell;
use ::std::cell::Ref;
use ::std::cell::RefCell;
use ::std::cell::RefMut;
use ::std::collections::BTreeMap;
use ::std::cmp::Eq;
use ::std::cmp::max;
use ::std::cmp::min;
use ::std::cmp::Ord;
use ::std::cmp::Ordering;
use ::std::cmp::PartialOrd;
use ::std::error;
use ::std::ffi::CString;
use ::std::fmt;
use ::std::fmt::Debug;
use ::std::fmt::Formatter;
use ::std::fs::read;
use ::std::hash::BuildHasher;
use ::std::hash::Hash;
use ::std::hash::Hasher;
use ::std::io;
use ::std::marker::PhantomData;
use ::std::mem::align_of;
use ::std::mem::ManuallyDrop;
use ::std::mem::needs_drop;
use ::std::mem::size_of;
use ::std::mem::transmute;
use ::std::mem::transmute_copy;
use ::std::mem::uninitialized;
use ::std::mem::zeroed;
use ::std::ops::Add;
use ::std::ops::AddAssign;
use ::std::ops::Deref;
use ::std::ops::Div;
use ::std::ops::Index;
use ::std::ops::Mul;
use ::std::ops::Shl;
use ::std::ops::Shr;
use ::std::ops::Sub;
use ::std::ops::SubAssign;
use ::std::path::Path;
use ::std::ptr::copy_nonoverlapping;
use ::std::ptr::drop_in_place;
use ::std::ptr::NonNull;
use ::std::ptr::null;
use ::std::ptr::null_mut;
use ::std::ptr::write_unaligned;
use ::std::rc::Rc;
use ::std::slice::from_raw_parts;
use ::std::slice::from_raw_parts_mut;
use ::std::thread::sleep;
use ::std::time::Duration;

