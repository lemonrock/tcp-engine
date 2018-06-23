// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Using the Bandwith-Delay Product (BDP) calculation, it is possible to compute a maximum buffer size - receive window - for a connection.
///
/// BDP = bits-per-second x (round-trip-time-in-milliseconds / 1000)
///
/// Buffer Size in Bytes = BDP / 8
///
/// From Wikipedia: A T1 line at 1.5Mbit / second with a 512ms round-triptime (RTT) gives a Buffer Size of 96,187 bytes (1,500,000 * 513 / 1000) / 8, ie a 94Kb buffer.
///
/// The maximum receive window is 1Gb, eg:-
///
/// * A 1Gbit/s link with a RTT of 8000ms (8s)
/// * A 10Gbit/s link with a RTT of 800ms
/// * A 100Gbit/s link with a RTT of 80ms
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct SegmentWindowSize(u16);

impl From<u16> for SegmentWindowSize
{
	#[inline(always)]
	fn from(value: u16) -> Self
	{
		SegmentWindowSize(value)
	}
}

impl From<NetworkEndianU16> for SegmentWindowSize
{
	#[inline(always)]
	fn from(value: NetworkEndianU16) -> Self
	{
		SegmentWindowSize(value.to_native_endian())
	}
}

impl Into<NetworkEndianU16> for SegmentWindowSize
{
	#[inline(always)]
	fn into(self) -> NetworkEndianU16
	{
		NetworkEndianU16::from_native_endian(self.0)
	}
}

impl Shl<Wind> for SegmentWindowSize
{
	type Output = Self;
	
	fn shl(self, rhs: Wind) -> Self::Output
	{
		self << rhs.Scale
	}
}

impl Shl<WindowScaleOption> for SegmentWindowSize
{
	type Output = Self;
	
	fn shl(self, rhs: WindowScaleOption) -> Self::Output
	{
		let scalar: u8 = rhs.into();
		WindowSize::from((self.0 as u32) << scalar)
	}
}

impl SegmentWindowSize
{
	#[inline(always)]
	pub(crate) const fn from_network_endian_u16(value: NetworkEndianU16) -> Self
	{
		Self(value)
	}
}
