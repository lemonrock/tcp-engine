// This file is part of tcp_engine. It is subject to the license terms in the COPYRIGHT file found in the top_level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp_engine/master/COPYRIGHT. No part of tcp_engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2018 The developers of tcp_engine. See the COPYRIGHT file in the top_level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp_engine/master/COPYRIGHT.


#![allow(non_upper_case_globals)]
#![deny(missing_docs)]
#![feature(const_fn)]


//! # tcp_engine_authentication
//!


extern crate arrayvec;
extern crate md5;
extern crate tcp_engine_check_sum;
extern crate tcp_engine_network_endian;
extern crate tcp_engine_internet_protocol;


use ::arrayvec::ArrayVec;
use ::md5::Md5;
use ::std::ptr::NonNull;
use ::tcp_engine_check_sum::Digest;
use ::tcp_engine_check_sum::Layer4ProtocolNumber;
use ::tcp_engine_network_endian::*;
use ::tcp_engine_internet_protocol::InternetProtocolAddress;


include!("Md5AuthenticationConnectionIdentifier.rs");
include!("Md5PreSharedSecretKey.rs");
include!("TcpSegmentWithAuthenticationData.rs");
