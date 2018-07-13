// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2018 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#![allow(non_upper_case_globals)]
#![deny(missing_docs)]
#![feature(const_fn)]


//! # tcp-engine-check-sum
//!

extern crate digest;
extern crate tcp_engine_network_endian;


pub use ::digest::Digest;
use ::std::fmt;
use ::std::fmt::Display;
use ::std::fmt::Formatter;
use ::std::mem::size_of;
use ::std::mem::zeroed;
use ::std::ptr::NonNull;
use ::tcp_engine_network_endian::*;


include!("InternetProtocolVersion4PseudoHeader.rs");
include!("InternetProtocolVersion6PseudoHeader.rs");
include!("Layer4ProtocolNumber.rs");
include!("Rfc1141CompliantCheckSum.rs");
