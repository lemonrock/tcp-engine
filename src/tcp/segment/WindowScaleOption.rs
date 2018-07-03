// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct WindowScaleOption(u8);

impl Default for WindowScaleOption
{
	#[inline(always)]
	fn default() -> Self
	{
		WindowScaleOption::Zero
	}
}

impl Into<u8> for WindowScaleOption
{
	#[inline(always)]
	fn into(self) -> u8
	{
		self.0
	}
}

impl Into<u32> for WindowScaleOption
{
	#[inline(always)]
	fn into(self) -> u32
	{
		self.0 as u32
	}
}

impl Into<usize> for WindowScaleOption
{
	#[inline(always)]
	fn into(self) -> usize
	{
		self.0 as usize
	}
}

impl WindowScaleOption
{
	pub(crate) const Kind: u8 = 3;
	
	pub(crate) const Zero: Self = WindowScaleOption(0);
	
	pub(crate) const BufferSizeOf256Kb: Self = WindowScaleOption(2);
	
	pub(crate) const Maximum: Self = WindowScaleOption(14);
	
	pub(crate) const KnownLength: usize = 3;
	
	pub(crate) const EquivalentToNoWindowScale: Self = Self::Zero;
}
