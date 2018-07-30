// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2018 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#![allow(non_upper_case_globals)]
#![deny(missing_docs)]
#![feature(const_fn)]
#![feature(core_intrinsics)]


//! # tcp-engine-internet-protocol
//!


#[macro_use] extern crate likely;
extern crate tcp_engine_check_sum;
extern crate tcp_engine_network_endian;


use ::std::mem::transmute;
use ::std::ptr::NonNull;
use ::tcp_engine_check_sum::*;
use ::tcp_engine_network_endian::*;


include!("ExplicitCongestionNotification.rs");
include!("InternetProtocolAddress.rs");
include!("MaximumSegmentSize.rs");
