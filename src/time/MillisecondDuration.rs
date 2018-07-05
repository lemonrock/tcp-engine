// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Represents a duration in milliseconds.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct MillisecondDuration(u64);

impl From<u8> for MillisecondDuration
{
	#[inline(always)]
	fn from(milliseconds: u8) -> Self
	{
		MillisecondDuration(milliseconds as u64)
	}
}

impl From<u16> for MillisecondDuration
{
	#[inline(always)]
	fn from(milliseconds: u16) -> Self
	{
		MillisecondDuration(milliseconds as u64)
	}
}

impl From<u32> for MillisecondDuration
{
	#[inline(always)]
	fn from(milliseconds: u32) -> Self
	{
		MillisecondDuration(milliseconds as u64)
	}
}

impl From<u64> for MillisecondDuration
{
	#[inline(always)]
	fn from(milliseconds: u64) -> Self
	{
		MillisecondDuration(milliseconds)
	}
}

impl Into<u64> for MillisecondDuration
{
	#[inline(always)]
	fn into(self) -> u64
	{
		self.0
	}
}

impl Into<TickDuration> for MillisecondDuration
{
	#[inline(always)]
	fn into(self) -> u64
	{
		TickDuration::milliseconds_to_ticks_rounded_down(self.0)
	}
}

impl Add for MillisecondDuration
{
	type Output = Self;
	
	#[inline(always)]
	fn sub(self, rhs: Self) -> Self::Output
	{
		self.0 + rhs.0
	}
}

impl Sub for MillisecondDuration
{
	type Output = Self;
	
	#[inline(always)]
	fn sub(self, rhs: Self) -> Self::Output
	{
		self.0 - rhs.0
	}
}

impl Mul<u64> for MillisecondDuration
{
	type Output = Self;
	
	#[inline(always)]
	fn div(self, rhs: u64) -> Self::Output
	{
		MillisecondDuration(self.0.saturating_mul(rhs))
	}
}

impl Div for MillisecondDuration
{
	type Output = u64;
	
	#[inline(always)]
	fn div(self, rhs: Self) -> Self::Output
	{
		self.0 / rhs.0
	}
}

impl Default for MillisecondDuration
{
	#[inline(always)]
	fn default() -> Self
	{
		Self::Zero
	}
}

impl MillisecondDuration
{
	/// Zero.
	pub const Zero: Self = Self::from_milliseconds(0);
	
	/// One second.
	pub const OneSecond: Self = Self::from_seconds(1);
	
	/// 3 seconds.
	pub const ThreeSeconds: Self = Self::from_seconds(3);
	
	/// 5 seconds.
	pub const FiveSeconds: Self = Self::from_seconds(5);
	
	/// Ten seconds.
	pub const TenSeconds: Self = Self::from_seconds(10);
	
	/// Fifteen seconds.
	pub const FifteenSeconds: Self = Self::from_seconds(15);
	
	/// Thirty seconds.
	pub const ThirtySeconds: Self = Self::from_seconds(30);
	
	/// Two minutes.
	pub const TwoMinutes: Self = Self::from_minutes(2);
	
	/// Five minutes.
	pub const FiveMinutes: Self = Self::from_minutes(5);
	
	//  // 7,200,000 (two hours)
	/// Two hours
	pub const TwoHours: Self = Self::from_seconds(1);
	
	const MillisecondsPerSecond: u64 = 1_000;
	
	/// From tick duration.
	#[inline(always)]
	pub const fn from_tick_duration(tick_duration: TickDuration) -> Self
	{
		Self::from_milliseconds(tick_duration.0 * Tick::MillisecondsPerTick)
	}
	
	/// From milliseconds.
	#[inline(always)]
	pub const fn from_milliseconds(milliseconds: u64) -> Self
	{
		MillisecondDuration(milliseconds)
	}
	
	/// From seconds.
	#[inline(always)]
	pub const fn from_seconds(seconds: u64) -> Self
	{
		Self::from_milliseconds(seconds * Self::MillisecondsPerSecond)
	}
	
	/// From minutes.
	#[inline(always)]
	pub const fn from_minutes(minutes: u64) -> Self
	{
		const SecondsPerMinute: u64 = 60;
		Self::from_seconds(minutes * SecondsPerMinute)
	}
	
	/// From hours.
	#[inline(always)]
	pub const fn from_hours(hours: u64) -> Self
	{
		const MinutesPerHour: u64 = 60;
		Self::from_minutes(hours * MinutesPerHour)
	}
	
	/// Is zero.
	#[inline(always)]
	pub fn is_zero(self) -> bool
	{
		self.0 == Self::Zero.0
	}
	
	/// Is not zero.
	#[inline(always)]
	pub fn is_not_zero(self) -> bool
	{
		self.0 != Self::Zero.0
	}
	
	/// As seconds, rounded down.
	#[inline(always)]
	pub fn seconds_rounded_down(self) -> u64
	{
		self.0 / Self::MillisecondsPerSecond
	}
	
	/// Absolute difference, `|self - right|`.
	#[inline(always)]
	pub fn absolute_difference(self, right: Self) -> MillisecondDuration
	{
		if self > right
		{
			self - right
		}
		else
		{
			right - self
		}
	}
}
