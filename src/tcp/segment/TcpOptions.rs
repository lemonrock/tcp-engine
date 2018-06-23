// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct TcpOptions
{
	pub(crate) maximum_segment_size: Option<MaximumSegmentSizeOption>,
	pub(crate) window_scale: Option<WindowScaleOption>,
	pub(crate) selective_acknowledgment_permitted: bool,
	pub(crate) selective_acknowledgment: Option<SelectiveAcknowledgmentOption>,
	pub(crate) timestamps: Option<TimestampsOption>,
	pub(crate) user_time_out: Option<UserTimeOutOption>,
	pub(crate) authentication: Option<AuthenticationOption>,
}

impl TcpOptions
{
	const LengthOverhead: usize = 2;
	
	#[inline(always)]
	fn has_maximum_segment_size(&self) -> bool
	{
		self.maximum_segment_size.is_some()
	}
	
	#[inline(always)]
	fn has_window_scale(&self) -> bool
	{
		self.window_scale.is_some()
	}
	
	#[inline(always)]
	fn has_selective_acknowledgment_permitted(&self) -> bool
	{
		self.selective_acknowledgment_permitted
	}
	
	#[inline(always)]
	fn has_selective_acknowledgment(&self) -> bool
	{
		self.selective_acknowledgment.is_some()
	}
	
	#[inline(always)]
	fn has_timestamps(&self) -> bool
	{
		self.timestamps.is_some()
	}
	
	#[inline(always)]
	fn has_user_time_out(&self) -> bool
	{
		self.user_time_out.is_some()
	}
	
	#[inline(always)]
	fn has_authentication(&self) -> bool
	{
		self.authentication.is_some()
	}
	
	#[inline(always)]
	fn parse_option_kind_without_checks(pointer_to_option_kind: usize) -> u8
	{
		let length = unsafe { *(pointer_to_option_kind as *const u8) };
		length
	}
	
	#[inline(always)]
	fn parse_option_length_without_checks(pointer_to_length: usize) -> u8
	{
		let length = unsafe { *(pointer_to_length as *const u8) };
		length
	}
}
