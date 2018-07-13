// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2018 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![deny(missing_docs)]
#![feature(const_fn)]
#![feature(core_intrinsics)]


//! # tcp-engine-tcp-domain
//!


#[macro_use] extern crate bitflags;
extern crate hyper_thread_random;
extern crate tcp_engine_authentication;
extern crate tcp_engine_check_sum;
extern crate tcp_engine_internet_protocol;
#[macro_use] extern crate tcp_engine_likely;
extern crate tcp_engine_network_endian;
extern crate tcp_engine_ports;
extern crate tcp_engine_time;


use self::tcp_options::*;
use ::hyper_thread_random::generate_hyper_thread_safe_random_u32;
use ::std::cmp::max;
use ::std::cmp::min;
use ::std::cmp::Ordering;
use ::std::marker::PhantomData;
use ::std::mem::size_of;
use ::std::mem::zeroed;
use ::std::ops::Add;
use ::std::ops::AddAssign;
use ::std::ops::Index;
use ::std::ops::Shl;
use ::std::ops::Shr;
use ::std::ops::Sub;
use ::std::ops::SubAssign;
use ::std::ptr::NonNull;
use ::std::slice::from_raw_parts;
use ::tcp_engine_authentication::Authentication;
use ::tcp_engine_authentication::Digest;
use ::tcp_engine_authentication::TcpSegmentWithAuthenticationData;
use ::tcp_engine_check_sum::Rfc1141CompliantCheckSum;
use ::tcp_engine_internet_protocol::InternetProtocolAddress;
use ::tcp_engine_network_endian::*;
use ::tcp_engine_ports::*;
use ::tcp_engine_time::*;


/// TCP options.
#[macro_use] pub mod tcp_options;


include!("WrappingSequenceNumber.adjust_comparison_for_wrap_around.rs");


include!("DataOffsetReservedBitsNonceSumFlag.rs");
include!("Flags.rs");
include!("InitialWindowSize.rs");
include!("SegmentWindowSize.rs");
include!("SelectiveAcknowledgmentBlock.rs");
include!("State.rs");
include!("TcpSegment.rs");
include!("TcpFixedHeader.rs");
include!("Timestamping.rs");
include!("WindowSize.rs");
include!("WrappingSequenceNumber.rs");
include!("WrappingTimestamp.rs");
