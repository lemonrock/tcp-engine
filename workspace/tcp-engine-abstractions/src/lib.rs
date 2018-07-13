// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2018 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![deny(missing_docs)]


//! # tcp-engine-abstractions
//!


extern crate tcp_engine_internet_protocol;
extern crate tcp_engine_network_endian;
extern crate tcp_engine_ports;
extern crate tcp_engine_tcp_domain;


use ::std::ptr::NonNull;
use ::tcp_engine_internet_protocol::ExplicitCongestionNotification;
use ::tcp_engine_internet_protocol::InternetProtocolAddress;
use ::tcp_engine_network_endian::NetworkEndianU16;
use ::tcp_engine_ports::*;
use ::tcp_engine_tcp_domain::TcpSegment;


include!("CheckSumLayering.rs");
include!("NetworkPacket.rs");
include!("TransmissionControlBlockAbstractions.rs");
include!("TransmissionControlBlockEventsReceiver.rs");
include!("TransmissionControlBlockEventsReceiverCreator.rs");
include!("TransmissionControlBlockKey.rs");
