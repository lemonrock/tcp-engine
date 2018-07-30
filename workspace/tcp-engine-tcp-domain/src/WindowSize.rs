// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Window size after window shift has been applied.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct WindowSize(u32);

impl From<u32> for WindowSize
{
	#[inline(always)]
	fn from(value: u32) -> Self
	{
		WindowSize(value)
	}
}

impl Into<u32> for WindowSize
{
	#[inline(always)]
	fn into(self) -> u32
	{
		self.0
	}
}

impl Shr<WindowScaleOption> for WindowSize
{
	type Output = SegmentWindowSize;
	
	fn shr(self, rhs: WindowScaleOption) -> Self::Output
	{
		let scalar: u8 = rhs.into();
		SegmentWindowSize::from((self.0 >> scalar) as u16)
	}
}

impl WindowSize
{
	/// Zero.
	pub const Zero: WindowSize = WindowSize(0);
	
	/// Maximum.
	pub const Maximum: WindowSize = WindowSize(65_535 << WindowScaleOption::Maximum.0);
	
	/// Create a new instance.
	#[inline(always)]
	pub const fn new(window_size: u32) -> Self
	{
		WindowSize(window_size)
	}
	
	/// Is zero?
	#[inline(always)]
	pub fn is_zero(self) -> bool
	{
		self.0 == Self::Zero.0
	}
	
	/// Similar to into() but constant.
	#[inline(always)]
	pub const fn value(self) -> u32
	{
		self.0
	}
}
