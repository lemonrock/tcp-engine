// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2018 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#![allow(non_upper_case_globals)]
#![deny(missing_docs)]
#![feature(const_fn)]


//! # tcp-engine-ports
//!

extern crate hyper_thread_random;
extern crate tcp_engine_network_endian;


use ::hyper_thread_random::generate_hyper_thread_safe_random_u16;
use ::std::fmt;
use ::std::fmt::Debug;
use ::std::mem::transmute;
use ::std::mem::uninitialized;
use ::std::mem::zeroed;
use ::std::ops::Index;
use ::tcp_engine_network_endian::NetworkEndianU16;


include!("PortBitSet.rs");
include!("PortCombinationValidity.rs");
include!("Ports.rs");
include!("RemotePortLocalPort.rs");
include!("SourcePortDestinationPort.rs");
