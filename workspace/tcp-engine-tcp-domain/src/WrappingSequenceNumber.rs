// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A native-endian wrapping sequence number (ie one that starts again from zero once the maximum is exceeded).
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct WrappingSequenceNumber(u32);

impl PartialOrd for WrappingSequenceNumber
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Self) -> Option<Ordering>
	{
		Some(self.cmp(other))
	}
}

impl Ord for WrappingSequenceNumber
{
	#[inline(always)]
	fn cmp(&self, other: &Self) -> Ordering
	{
		use self::Ordering::*;
		
		let us = self.0;
		let them = other.0;
		
		adjust_comparison_for_wrap_around!(us, them, {Less}, {Greater}, {Equal})
	}
}

impl From<u32> for WrappingSequenceNumber
{
	#[inline(always)]
	fn from(value: u32) -> Self
	{
		WrappingSequenceNumber(value)
	}
}

impl From<NetworkEndianU32> for WrappingSequenceNumber
{
	#[inline(always)]
	fn from(value: NetworkEndianU32) -> Self
	{
		WrappingSequenceNumber(value.to_native_endian())
	}
}

impl From<MonotonicMillisecondTimestamp> for WrappingSequenceNumber
{
	#[inline(always)]
	fn from(value: MonotonicMillisecondTimestamp) -> Self
	{
		WrappingSequenceNumber(value.into())
	}
}

impl Into<NetworkEndianU32> for WrappingSequenceNumber
{
	#[inline(always)]
	fn into(self) -> NetworkEndianU32
	{
		NetworkEndianU32::from_native_endian(self.0)
	}
}

impl Into<u32> for WrappingSequenceNumber
{
	#[inline(always)]
	fn into(self) -> u32
	{
		self.0
	}
}

impl Into<usize> for WrappingSequenceNumber
{
	#[inline(always)]
	fn into(self) -> usize
	{
		self.0 as usize
	}
}

impl Add<u32> for WrappingSequenceNumber
{
	type Output = Self;
	
	#[inline(always)]
	fn add(self, other: u32) -> Self::Output
	{
		self.increment_u32(other)
	}
}

impl Add<usize> for WrappingSequenceNumber
{
	type Output = Self;
	
	#[inline(always)]
	fn add(self, other: usize) -> Self::Output
	{
		self.increment_u32(other as u32)
	}
}

impl Add<WindowSize> for WrappingSequenceNumber
{
	type Output = Self;
	
	#[inline(always)]
	fn add(self, other: WindowSize) -> Self::Output
	{
		self.increment_u32(other.into())
	}
}

impl AddAssign<u32> for WrappingSequenceNumber
{
	#[inline(always)]
	fn add_assign(&mut self, other: u32)
	{
		self.increment_u32_mut(other)
	}
}

impl AddAssign<WindowSize> for WrappingSequenceNumber
{
	#[inline(always)]
	fn add_assign(&mut self, other: WindowSize)
	{
		self.increment_u32_mut(other.into())
	}
}

impl Sub for WrappingSequenceNumber
{
	type Output = u32;
	
	#[inline(always)]
	fn sub(self, other: Self) -> Self::Output
	{
		self.0.wrapping_sub(other.0)
	}
}

impl Sub<u32> for WrappingSequenceNumber
{
	type Output = Self;
	
	#[inline(always)]
	fn sub(self, other: u32) -> Self::Output
	{
		self.decrement_u32(other)
	}
}

impl SubAssign<u32> for WrappingSequenceNumber
{
	#[inline(always)]
	fn sub_assign(&mut self, other: u32)
	{
		self.decrement_u32_mut(other)
	}
}

impl Sub<WindowSize> for WrappingSequenceNumber
{
	type Output = Self;
	
	#[inline(always)]
	fn sub(self, other: WindowSize) -> Self::Output
	{
		self.decrement_u32(other.into())
	}
}

impl SubAssign<WindowSize> for WrappingSequenceNumber
{
	#[inline(always)]
	fn sub_assign(&mut self, other: WindowSize)
	{
		self.decrement_u32_mut(other.into())
	}
}

impl WrappingSequenceNumber
{
	/// Zero.
	pub const Zero: Self = WrappingSequenceNumber(0);
	
	/// Create a new instance.
	#[inline(always)]
	pub const fn new(value: u32) -> Self
	{
		WrappingSequenceNumber(value)
	}
	
	/// Is zero?
	#[inline(always)]
	pub fn is_zero(self) -> bool
	{
		self.0 == Self::Zero.0
	}
	
	/// Is not zero?
	#[inline(always)]
	pub fn is_not_zero(self) -> bool
	{
		self.0 != Self::Zero.0
	}
	
	/// Relative difference.
	#[inline(always)]
	pub fn relative_difference(self, other: Self) -> i32
	{
		let us = self.0;
		let them = other.0;
		
		adjust_comparison_for_wrap_around!
		(
			us,
			them,
			{-(them.wrapping_sub(us) as i32)},
			{us.wrapping_sub(them) as i32},
			{0}
		)
	}
	
	/// Next.
	#[inline(always)]
	pub fn next(self) -> Self
	{
		self.increment_u32(1)
	}
	
	/// Increment by length in bytes.
	#[inline(always)]
	pub fn increment_by_length_in_bytes(self, increment_in_bytes: usize) -> Self
	{
		self.increment_u32(increment_in_bytes as u32)
	}
	
	/// Increment (in place).
	#[inline(always)]
	pub fn increment_u32_mut(&mut self, increment: u32)
	{
		*self = self.increment_u32(increment)
	}
	
	/// Increment.
	#[inline(always)]
	pub fn increment_u32(self, increment: u32) -> Self
	{
		WrappingSequenceNumber(self.0.wrapping_add(increment))
	}
	
	/// Decrement (in place).
	#[inline(always)]
	pub fn decrement_u32_mut(&mut self, decrement: u32)
	{
		*self = self.decrement_u32(decrement)
	}
	
	/// Decrement.
	#[inline(always)]
	pub fn decrement_u32(self, decrement: u32) -> Self
	{
		WrappingSequenceNumber(self.0.wrapping_sub(decrement))
	}
	
	/// Do the sequence numbers differ so much that wrap around could have happened more than once?
	#[inline(always)]
	pub fn sequence_numbers_differ_by_too_much(self, other: Self) -> bool
	{
		if self.0 >= other.0
		{
			Self::difference_exceeds_wrap_around(self.0, other.0)
		}
		else
		{
			Self::difference_exceeds_wrap_around(other.0, self.0)
		}
	}
	
	#[inline(always)]
	fn difference_exceeds_wrap_around(greater: u32, lesser: u32) -> bool
	{
		const WrapAroundThreshold: u32 = ::std::i32::MAX as u32;
		
		(greater - lesser) > WrapAroundThreshold
	}
}
