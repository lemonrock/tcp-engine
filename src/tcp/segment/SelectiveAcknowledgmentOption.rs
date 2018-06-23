// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


// This structure's layout is very similar to that which would be created by using a Rust enum instead.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct SelectiveAcknowledgmentOption
{
	number_of_blocks: u8,
	first_block: SelectiveAcknowledgmentBlock,
	second_block: Option<SelectiveAcknowledgmentBlock>,
	third_block: Option<SelectiveAcknowledgmentBlock>,
	fourth_block: Option<SelectiveAcknowledgmentBlock>,
}

impl SelectiveAcknowledgmentOption
{
	pub(crate) const Kind: u8 = 5;
	
	pub(crate) const SelectiveAcknowledgmentPermittedOptionKind: u8 = 4;
	
	pub(crate) const SelectiveAcknowledgmentPermittedOptionKnownLength: usize = 2;
	
	const OptionTypeAndLengthOverhead: usize = 2;
	
	pub(crate) const BlockLength: usize = 8;
	
	pub(crate) const OneBlockLength: usize = Self::OptionTypeAndLengthOverhead + BlockLength;
	
	pub(crate) const TwoBlocksLength: usize = OneBlockLength + BlockLength;
	
	pub(crate) const ThreeBlocksLength: usize = TwoBlocksLength + BlockLength;
	
	pub(crate) const FourBlocksLength: usize = ThreeBlocksLength + BlockLength;
	
	#[inline(always)]
	pub(crate) fn option_length(&self) -> usize
	{
		Self::OptionTypeAndLengthOverhead + (self.number_of_blocks * Self::BlockLength)
	}
	
	#[inline(always)]
	pub(crate) fn number_of_blocks(&self) -> u8
	{
		self.number_of_blocks
	}
	
	#[inline(always)]
	pub(crate) fn first_block(&self) -> SelectiveAcknowledgmentBlock
	{
		self.first_block
	}
	
	#[inline(always)]
	pub(crate) fn second_block(&self) -> SelectiveAcknowledgmentBlock
	{
		self.second_block.unwrap()
	}
	
	#[inline(always)]
	pub(crate) fn third_block(&self) -> SelectiveAcknowledgmentBlock
	{
		self.third_block.unwrap()
	}
	
	#[inline(always)]
	pub(crate) fn fourth_block(&self) -> SelectiveAcknowledgmentBlock
	{
		self.fourth_block.unwrap()
	}
	
	#[inline(always)]
	pub(crate) fn one_block(first_block: SelectiveAcknowledgmentBlock) -> Self
	{
		SelectiveAcknowledgmentOption
		{
			number_of_blocks: 1,
			first_block,
			second_block: None,
			third_block: None,
			fourth_block: None,
		}
	}
	
	#[inline(always)]
	pub(crate) fn two_blocks(first_block: SelectiveAcknowledgmentBlock, second_block: SelectiveAcknowledgmentBlock) -> Self
	{
		SelectiveAcknowledgmentOption
		{
			number_of_blocks: 2,
			first_block,
			second_block: Some(second_block),
			third_block: None,
			fourth_block: None,
		}
	}
	
	#[inline(always)]
	pub(crate) fn three_blocks(first_block: SelectiveAcknowledgmentBlock, second_block: SelectiveAcknowledgmentBlock, third_block: SelectiveAcknowledgmentBlock) -> Self
	{
		SelectiveAcknowledgmentOption
		{
			number_of_blocks: 3,
			first_block,
			second_block: Some(second_block),
			third_block: Some(third_block),
			fourth_block: None,
		}
	}
	
	#[inline(always)]
	pub(crate) fn four_blocks(first_block: SelectiveAcknowledgmentBlock, second_block: SelectiveAcknowledgmentBlock, third_block: SelectiveAcknowledgmentBlock, fourth_block: SelectiveAcknowledgmentBlock) -> Self
	{
		SelectiveAcknowledgmentOption
		{
			number_of_blocks: 4,
			first_block,
			second_block: Some(second_block),
			third_block: Some(third_block),
			fourth_block: Some(fourth_block),
		}
	}
}
