// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2018 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![deny(missing_docs)]
#![feature(const_fn)]
#![feature(core_intrinsics)]
#![feature(asm)]
#![feature(int_to_from_bytes)]


//! # tcp-engine
//!


extern crate arrayvec;
#[macro_use] extern crate bitflags;
extern crate hyper_thread_random;
extern crate libc;
#[macro_use] extern crate memoffset;
extern crate num_traits;
extern crate sha2;
extern crate siphasher;
#[cfg(not(all(unix, not(any(target_os = "macos", target_os = "ios")))))] extern crate time;


use self::check_sums::*;
use self::network_endian::*;
use self::packets::*;
use self::ports::*;
use self::time::*;


/// Check sums.
pub mod check_sums;


pub(crate) mod network_endian;


pub(crate) mod ports;


/// Transmission Control Protocol (TCP).
pub mod tcp;


/// Time.
pub mod time;


use ::arrayvec::ArrayVec;
use ::hyper_thread_random::generate_hyper_thread_safe_random_u32;
use ::hyper_thread_random::generate_hyper_thread_safe_random_u64;
use ::sha2::Digest;
use ::sha2::Sha256;
use ::siphasher::sip::SipHasher24;
use ::std::cell::Cell;
use ::std::cell::Ref;
use ::std::cell::RefCell;
use ::std::cell::RefMut;
use ::std::collections::BTreeMap;
use ::std::collections::HashMap;
use ::std::cmp::max;
use ::std::cmp::min;
use ::std::cmp::Ord;
use ::std::cmp::Ordering;
use ::std::cmp::PartialOrd;
use ::std::error;
use ::std::fmt;
use ::std::fmt::Debug;
use ::std::fmt::Formatter;
use ::std::fs::read;
use ::std::hash::BuildHasher;
use ::std::hash::Hasher;
use ::std::marker::PhantomData;
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
use ::std::ops::Shl;
use ::std::ops::Shr;
use ::std::ops::Sub;
use ::std::ops::SubAssign;
use ::std::ptr::NonNull;
use ::std::ptr::null;
use ::std::ptr::null_mut;
use ::std::thread::sleep;
use ::std::time::Duration;


include!("ContiguousPacket.rs");
include!("ExplicitCongestionNotification.rs");
include!("InternetProtocolAddress.rs");
include!("likely.rs");
include!("unlikely.rs");
