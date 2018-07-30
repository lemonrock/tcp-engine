// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct SortedCommonMaximumSegmentSizes(&'static [u16]);

impl SortedCommonMaximumSegmentSizes
{
	const MaximumEntries: usize = 8;
	
	#[inline(always)]
	pub(crate) fn new<Address: InternetProtocolAddress>() -> Self
	{
		let table = Address::sorted_common_maximum_segment_sizes();
		debug_assert_ne!(table.len(), 0, "table can not be empty");
		debug_assert!(table.len() <= Self::MaximumEntries, "table can not have more than '{}' entries", Self::MaximumEntries);
		
		SortedCommonMaximumSegmentSizes(table)
	}
	
	#[inline(always)]
	pub(crate) fn encode_maximum_segment_size_as_index(self, maximum_segment_size_option: MaximumSegmentSizeOption) -> u8
	{
		let maximum_segment_size = maximum_segment_size_option.to_native_endian();
		
		let mut previous = self.length();
		while previous != 0
		{
			previous -= 1;
			let adjusted_maximum_segment_size = self.adjusted_maximum_segment_size(previous);
			if maximum_segment_size >= adjusted_maximum_segment_size
			{
				return previous as u8
			}
		}
		0
	}
	
	#[inline(always)]
	pub(crate) fn decode_maximum_segment_size_from_index(self, index: u8) -> u16
	{
		let index = index as usize;
		debug_assert!(index < Self::MaximumEntries, "index {} exceeds MaximumEntries {}", index, Self::MaximumEntries);
		
		self.adjusted_maximum_segment_size(index)
	}
	
	#[inline(always)]
	fn length(self) -> usize
	{
		self.0.len()
	}
	
	#[inline(always)]
	fn adjusted_maximum_segment_size(self, index: usize) -> u16
	{
		*unsafe { self.0.get_unchecked(index) }
	}
}
