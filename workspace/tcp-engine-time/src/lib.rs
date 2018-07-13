// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2018 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#![allow(non_upper_case_globals)]
#![deny(missing_docs)]
#![feature(asm)]
#![feature(const_fn)]
#![feature(core_intrinsics)]


//! # tcp-engine-time
//!


#[macro_use] extern crate tcp_engine_likely;


use ::std::error;
use ::std::fs::read;
use ::std::mem::uninitialized;
use ::std::ops::Add;
use ::std::ops::AddAssign;
use ::std::ops::Div;
use ::std::ops::Mul;
use ::std::ops::Sub;
use ::std::thread::sleep;
use ::std::time::Duration;



include!("MillisecondDuration.rs");
include!("MonotonicMillisecondTimestamp.rs");
include!("Tick.rs");
include!("TickDuration.rs");
