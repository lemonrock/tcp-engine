// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A native-endian wrapping sequence number (ie one that starts again from zero once the maximum is exceeded).
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct WrappingSequenceNumber(u32);

macro_rules! adjust_comparison_for_wrap_around
{
	($us: ident, $them: ident, $less: block, $greater: block, $equal: block) =>
	{
		if $us > $them
		{
			if Self::difference_exceeds_wrap_around($us, $them)
			{
				$less
			}
			else
			{
				$greater
			}
		}
		else if $us < $them
		{
			if Self::difference_exceeds_wrap_around($them, $us)
			{
				$greater
			}
			else
			{
				$less
			}
		}
		else
		{
			$equal
		}
	}
}

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

impl Add<u32> for WrappingSequenceNumber
{
	type Output = Self;
	
	#[inline(always)]
	fn add(self, other: u32) -> Self::Output
	{
		self.increment_u32(other)
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

impl Add<WindowSize> for WrappingSequenceNumber
{
	type Output = Self;
	
	#[inline(always)]
	fn add(self, other: WindowSize) -> Self::Output
	{
		self.increment_u32(other.into())
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
	pub(crate) const Zero: Self = WrappingSequenceNumber(0);
	
	#[inline(always)]
	pub(crate) const fn new(value: u32) -> Self
	{
		WrappingSequenceNumber(value)
	}
	
	#[inline(always)]
	pub(crate) fn relative_difference(self, other: Self) -> i32
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
	
	#[inline(always)]
	pub(crate) fn next(self) -> Self
	{
		self.increment_u32(1)
	}
	
	#[inline(always)]
	pub(crate) fn increment_by_length_in_bytes(self, increment_in_bytes: usize) -> Self
	{
		self.increment_u32(increment_in_bytes as u32)
	}
	
	#[inline(always)]
	pub(crate) fn increment_u32_mut(&mut self, increment: u32)
	{
		*self = self.increment_u32(increment)
	}
	
	#[inline(always)]
	pub(crate) fn increment_u32(self, increment: u32) -> Self
	{
		WrappingSequenceNumber(self.0.wrapping_add(increment))
	}
	
	#[inline(always)]
	pub(crate) fn decrement_u32_mut(&mut self, decrement: u32)
	{
		*self = self.decrement_u32(decrement)
	}
	
	#[inline(always)]
	pub(crate) fn decrement_u32(self, decrement: u32) -> Self
	{
		WrappingSequenceNumber(self.0.wrapping_sub(decrement))
	}
	
	#[inline(always)]
	fn difference_exceeds_wrap_around(greater: u32, lesser: u32) -> bool
	{
		const WrapAroundThreshold: u32 = ::std::i32::MAX as u32;
		
		(greater - lesser) > WrapAroundThreshold
	}
}
