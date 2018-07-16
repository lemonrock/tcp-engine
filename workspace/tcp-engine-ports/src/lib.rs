// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2018 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#![allow(non_upper_case_globals)]
#![deny(missing_docs)]
#![feature(const_fn)]


//! # tcp-engine-ports
//!

extern crate hyper_thread_random;
extern crate tcp_engine_collections;
extern crate tcp_engine_internet_protocol;
extern crate tcp_engine_network_endian;
extern crate tcp_engine_time;


use ::hyper_thread_random::generate_hyper_thread_safe_random_u16;
use ::std::cell::UnsafeCell;
use ::std::cmp::Ordering;
use ::std::fmt;
use ::std::fmt::Debug;
use ::std::hash::Hash;
use ::std::hash::Hasher;
use ::std::mem::transmute;
use ::std::mem::uninitialized;
use ::std::mem::zeroed;
use ::std::ops::Index;
use ::tcp_engine_collections::least_recently_used_cache::LeastRecentlyUsedCacheWithExpiry;
use ::tcp_engine_internet_protocol::InternetProtocolAddress;
use ::tcp_engine_network_endian::NetworkEndianU16;
use ::tcp_engine_time::MillisecondDuration;
use ::tcp_engine_time::MonotonicMillisecondTimestamp;


include!("ConnectionIdentification.rs");
include!("PortBitSet.rs");
include!("PortCombinationValidity.rs");
include!("Ports.rs");
include!("RemotePortLocalPort.rs");
include!("SourcePortChooser.rs");
include!("SourcePortDestinationPort.rs");
