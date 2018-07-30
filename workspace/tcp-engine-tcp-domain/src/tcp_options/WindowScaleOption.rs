// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Window Scale Option.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct WindowScaleOption(pub(crate) u8);

impl Default for WindowScaleOption
{
	#[inline(always)]
	fn default() -> Self
	{
		WindowScaleOption::Zero
	}
}

impl From<u8> for WindowScaleOption
{
	#[inline(always)]
	fn from(value: u8) -> Self
	{
		WindowScaleOption(value)
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
	#[doc(hidden)]
	pub const Kind: u8 = 3;
	
	#[doc(hidden)]
	pub const KnownLength: usize = 3;
	
	/// Zero.
	pub const Zero: Self = WindowScaleOption(0);
	
	/// 256Kb buffer size.
	pub const BufferSizeOf256Kb: Self = WindowScaleOption(2);
	
	/// Maximum.
	pub const Maximum: Self = WindowScaleOption(14);
	
	/// Equivalent to no window scale supplied.
	pub const EquivalentToNoWindowScale: Self = Self::Zero;
}
