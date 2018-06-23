// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(C, packed)]
pub(crate) struct TimestampsOption
{
	/// "TSval"
	pub(crate) TSval: NetworkEndianU32,
	
	/// "TSecr"
	///
	/// RFC 7323, Section 3.2: "The TSecr field is valid if the ACK bit is set in the TCP header.
	/// If the ACK bit is not set in the outgoing TCP header, the sender of that segment SHOULD set the TSecr field to zero.
	/// ...
	/// When the ACK bit is not set, the receiver MUST ignore the value of the TSecr field."
	pub(crate) TSecr: NetworkEndianU32,
}

impl TimestampsOption
{
	pub(crate) const Kind: u8 = 8;
	
	pub(crate) const KnownLength: usize = 10;
	
	#[inline(always)]
	pub(crate) fn from_TSval_only(TSval: NetworkEndianU32) -> Self
	{
		Self
		{
			TSval,
			TSecr: NetworkEndianU32::Zero,
		}
	}
	
	#[inline(always)]
	pub(crate) fn from_TSval_and_TSecr(TSval: NetworkEndianU32, TSecr: NetworkEndianU32) -> Self
	{
		Self
		{
			TSval,
			TSecr,
		}
	}
}
