// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct SortedCommonWindowScales(&'static [u8]);

impl SortedCommonWindowScales
{
	const MaximumEntries: usize = 7;
	
	const SpecialIndexForNoWindowScaleOption: u8 = Self::MaximumEntries as u8;
	
	#[inline(always)]
	pub(crate) fn new<Address: InternetProtocolAddress>() -> Self
	{
		let table = Address::sorted_common_window_scales();
		debug_assert_ne!(table.len(), 0, "table can not be empty");
		debug_assert!(table.len() <= Self::MaximumEntries, "table can not have more than '{}' entries", Self::MaximumEntries);
		
		SortedCommonWindowScales(table)
	}
	
	#[inline(always)]
	pub(crate) fn encode_window_scale_as_index(self, window_scale_option: Option<WindowScaleOption>) -> u8
	{
		match window_scale_option
		{
			None => Self::SpecialIndexForNoWindowScaleOption,
			Some(window_scale_option) =>
			{
				let window_scale: u8 = window_scale_option.into();
				
				let mut previous = self.length();
				while previous != 0
				{
					previous -= 1;
					let adjusted_window_scale = self.adjusted_window_scale(previous);
					if window_scale >= adjusted_window_scale
					{
						return previous as u8
					}
				}
				0
			}
		}
	}
	
	#[inline(always)]
	pub(crate) fn decode_window_scale_from_index(self, index: u8) -> Option<u8>
	{
		debug_assert!(index <= Self::SpecialIndexForNoWindowScaleOption, "index {} exceeds SpecialIndexForNoWindowScaleOption {}", index, Self::SpecialIndexForNoWindowScaleOption);
		
		if index == Self::SpecialIndexForNoWindowScaleOption
		{
			None
		}
		else
		{
			Some(self.adjusted_window_scale(index as usize))
		}
	}
	
	#[inline(always)]
	fn length(self) -> usize
	{
		self.0.len()
	}
	
	#[inline(always)]
	fn adjusted_window_scale(self, index: usize) -> u8
	{
		*unsafe { self.0.get_unchecked(index) }
	}
}
