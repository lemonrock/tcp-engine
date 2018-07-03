// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Explicit congestion notification (ECN) value.
///
/// Defaults to `NotCapableTransport`.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExplicitCongestionNotification
{
	#[allow(missing_docs)]
	NotCapableTransport = 0b00,
	
	#[allow(missing_docs)]
	CapableTransportEctZero = 0b10,
	
	#[allow(missing_docs)]
	CapableTransportEctOne = 0b01,
	
	#[allow(missing_docs)]
	CongestionEncountered = 0b11,
}

impl Default for ExplicitCongestionNotification
{
	#[inline(always)]
	fn default() -> Self
	{
		ExplicitCongestionNotification::NotCapableTransport
	}
}

impl ExplicitCongestionNotification
{
	#[inline(always)]
	pub fn is_ect_set(self) -> bool
	{
		use self::ExplicitCongestionNotification::*;
		
		self == CapableTransportEctZero || self == CapableTransportEctOne
	}
	
	#[inline(always)]
	pub fn congestion_encountered(self) -> bool
	{
		self == ExplicitCongestionNotification::CongestionEncountered
	}
}
