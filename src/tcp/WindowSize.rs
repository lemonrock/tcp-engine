// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct WindowSize(u32);

impl From<u32> for SegmentWindowSize
{
	#[inline(always)]
	fn from(value: u32) -> Self
	{
		SegmentWindowSize(value)
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
	type Output = Self;
	
	fn shl(self, rhs: WindowScaleOption) -> Self::Output
	{
		let scalar: u8 = rhs.into();
		SegmentWindowSize::from((self.0 >> scalar) as u16)
	}
}

impl WindowSize
{
	pub(crate) const Zero: WindowSize = WindowSize(0);
	
	#[inline(always)]
	pub(crate) const fn new(window_size: u32) -> Self
	{
		WindowSize(window_size)
	}
}
