// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct TickDuration(u64);

impl Mul<u64> for TickDuration
{
	type Output = Self;
	
	#[inline(always)]
	fn mul(self, rhs: u64) -> Self::Output
	{
		TickDuration(self.0 * rhs)
	}
}

impl Into<u64> for TickDuration
{
	#[inline(always)]
	fn into(self) -> u64
	{
		self.0
	}
}

impl TickDuration
{
	pub const Zero: Self = TickDuration(0);
	
	#[inline(always)]
	pub const fn new(ticks: u64) -> Self
	{
		TickDuration(ticks)
	}
	
	#[inline(always)]
	pub fn milliseconds_to_ticks_rounded_down(milliseconds: MillisecondDuration) -> Self
	{
		let milliseconds: u64 = milliseconds.into();
		TickDuration(milliseconds / Tick::MillisecondsPerTick)
	}
	
	#[inline(always)]
	pub fn milliseconds_to_ticks_rounded_up(milliseconds: MillisecondDuration) -> Self
	{
		let milliseconds: u64 = milliseconds.into();
		let ticks_rounded_up = (milliseconds + Tick::MillisecondsPerTick - 1) / Tick::MillisecondsPerTick;
		TickDuration(ticks_rounded_up)
	}
	
	#[inline(always)]
	pub fn is_zero(self) -> bool
	{
		self.0 == Self::Zero.0
	}
}
