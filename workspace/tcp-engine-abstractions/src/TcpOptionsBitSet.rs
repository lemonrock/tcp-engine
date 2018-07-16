// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Maximum number of options: 2^8 = 256.
///
/// Maximum number of u64: 256 / 64 = 4.
#[derive(Default, Debug, Clone)]
pub(crate) struct TcpOptionsBitSet([u64; TcpOptionsBitSet::NumberOfElements]);

impl TcpOptionsBitSet
{
	const BitsPerElement: usize = 64;
	
	const NumberOfElements: usize = 2^8 / Self::BitsPerElement;
	
	#[inline(always)]
	pub(crate) fn new() -> Self
	{
		unsafe { zeroed() }
	}
	
	#[inline(always)]
	pub(crate) fn does_not_contain(&self, option_kind: u8) -> bool
	{
		// Could be potentially replaced by the `_bittest64()` intrinsic, which is not part of Rust's support today.
		
		let (element, bit_in_element_mask) = Self::element_and_bit_in_element_mask(option_kind);
		
		(unsafe { *self.0.get_unchecked(element) }) & bit_in_element_mask == 0
	}
	
	#[inline(always)]
	pub(crate) fn contains(&self, option_kind: u8) -> bool
	{
		!self.does_not_contain(option_kind)
	}
	
	#[inline(always)]
	pub(crate) fn insert(&mut self, option_kind: u8)
	{
		let (element, bit_in_element_mask) = Self::element_and_bit_in_element_mask(option_kind);
		
		unsafe { *self.0.get_unchecked_mut(element) |= bit_in_element_mask };
	}
	
	#[inline(always)]
	fn element_and_bit_in_element_mask(option_kind: u8) -> (usize, u64)
	{
		let bit_number = option_kind as usize;
		let element = bit_number / Self::BitsPerElement;
		let bit_in_element = bit_number % Self::BitsPerElement;
		let bit_in_element_mask = 1 << bit_in_element;
		
		(element, bit_in_element_mask)
	}
}

impl Index<u8> for TcpOptionsBitSet
{
	type Output = bool;
	
	#[inline(always)]
	fn index(&self, option_kind: u8) -> &bool
	{
		if self.contains(option_kind)
		{
			static True: bool = true;
			&True
		}
		else
		{
			static False: bool = false;
			&False
		}
	}
}
