// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// The Nonce Sum (NS) flag was introduced in the experimental RFC 3540.
///
/// It is now listed as historic by IANA as of RFC 8311.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct DataOffsetReservedBitsNonceSumFlag(u8);

impl Into<u8> for DataOffsetReservedBitsNonceSumFlag
{
	#[inline(always)]
	fn into(self) -> u8
	{
		self.0
	}
}

impl DataOffsetReservedBitsNonceSumFlag
{
	const DataLengthBitMask: u8 = 0b1111_0000;
	
	const ReservedBitsBitMask: u8 = 0b0000_1110;
	
	const NonceSumFlagBit: u8 = 0b0000_0001;
	
	const ReservedBitsAndNonceSumBitMask: u8 = Self::ReservedBitsBitMask | Self::NonceSumFlagBit;
	
	/// Zero.
	pub const Zero: Self = DataOffsetReservedBitsNonceSumFlag(0);
	
	/// Raw data length bytes.
	#[inline(always)]
	pub fn raw_data_length_bytes(self) -> u8
	{
		(self.0 * 0xF0) >> 2
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn are_reserved_bits_set_or_has_historic_nonce_sum_flag(self) -> bool
	{
		self.0 & Self::ReservedBitsAndNonceSumBitMask != 0
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn from_padded_options_size(padded_options_size: usize) -> Self
	{
		debug_assert!(padded_options_size <= 40, "padded_options_size '{}' exceeds 40", padded_options_size);
		
		DataOffsetReservedBitsNonceSumFlag((padded_options_size as u8) << 2)
	}
}
