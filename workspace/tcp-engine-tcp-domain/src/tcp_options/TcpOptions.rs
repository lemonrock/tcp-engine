// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// TCP options.
#[allow(missing_docs)]
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct TcpOptions
{
	pub maximum_segment_size: Option<MaximumSegmentSizeOption>,
	pub window_scale: Option<WindowScaleOption>,
	pub selective_acknowledgment_permitted: bool,
	pub selective_acknowledgment: Option<SelectiveAcknowledgmentOption>,
	pub timestamps: Option<TimestampsOption>,
	pub user_time_out: Option<UserTimeOutOption>,
	pub authentication: Option<AuthenticationOption>,
}

impl TcpOptions
{
	#[doc(hidden)]
	#[inline(always)]
	pub const LengthOverhead: usize = 2;
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn has_maximum_segment_size(&self) -> bool
	{
		self.maximum_segment_size.is_some()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn has_window_scale(&self) -> bool
	{
		self.window_scale.is_some()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn has_selective_acknowledgment_permitted(&self) -> bool
	{
		self.selective_acknowledgment_permitted
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn has_selective_acknowledgment(&self) -> bool
	{
		self.selective_acknowledgment.is_some()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn has_timestamps(&self) -> bool
	{
		self.timestamps.is_some()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn does_not_have_timestamps(&self) -> bool
	{
		self.timestamps.is_none()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn has_user_time_out(&self) -> bool
	{
		self.user_time_out.is_some()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn has_authentication(&self) -> bool
	{
		self.authentication.is_some()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn parse_option_kind_without_checks(pointer_to_option_kind: usize) -> u8
	{
		let length = unsafe { *(pointer_to_option_kind as *const u8) };
		length
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn parse_option_length_without_checks(pointer_to_length: usize) -> u8
	{
		let length = unsafe { *(pointer_to_length as *const u8) };
		length
	}
}
