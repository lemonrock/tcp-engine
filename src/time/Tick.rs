// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct Tick(u64);

impl Add<u64> for Tick
{
	type Output = Self;
	
	#[inline(always)]
	fn add(self, rhs: u64) -> Self::Output
	{
		Tick(self.0 + rhs)
	}
}

impl AddAssign<u64> for Tick
{
	#[inline(always)]
	fn add_assign(&mut self, other: u64)
	{
		self.0 += other
	}
}

impl Add<TickDuration> for Tick
{
	type Output = Self;
	
	#[inline(always)]
	fn add(self, rhs: TickDuration) -> Self::Output
	{
		Tick(self.0 + rhs.0)
	}
}

impl Sub<u64> for Tick
{
	type Output = Self;
	
	#[inline(always)]
	fn sub(self, rhs: u64) -> Self::Output
	{
		Tick(self.0 - rhs)
	}
}

impl Sub<Tick> for Tick
{
	type Output = TickDuration;
	
	#[inline(always)]
	fn sub(self, rhs: Self) -> Self::Output
	{
		TickDuration(self.0 - rhs.0)
	}
}

impl Div for Tick
{
	type Output = usize;
	
	#[inline(always)]
	fn div(self, rhs: Self) -> Self::Output
	{
		(self.0 / rhs.0) as usize
	}
}

impl Tick
{
	pub const Zero: Self = Tick(0);
	
	const MillisecondsPerTick: u64 = 128;
	
	#[inline(always)]
	pub fn now() -> Self
	{
		Self::milliseconds_to_ticks_rounded_down(MillisecondDuration(MonotonicMillisecondTimestamp::now().0))
	}
	
	#[inline(always)]
	pub(crate) const fn ring_slot_index(self, number_of_ring_slots: usize) -> usize
	{
		(self.0 as usize) % number_of_ring_slots
	}
	
	#[inline(always)]
	pub fn milliseconds_to_ticks_rounded_down(milliseconds: MillisecondDuration) -> Tick
	{
		let milliseconds = milliseconds.0;
		Tick(milliseconds / Self::MillisecondsPerTick)
	}
	
	#[inline(always)]
	pub fn milliseconds_to_ticks_rounded_up(milliseconds: MillisecondDuration) -> Tick
	{
		let milliseconds = milliseconds.0;
		let ticks_rounded_up = (milliseconds + Self::MillisecondsPerTick - 1) / Self::MillisecondsPerTick;
		Tick(ticks_rounded_up)
	}
	
	#[inline(always)]
	pub fn is_zero(self) -> bool
	{
		self.0 == Self::Zero.0
	}
}
