// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Modelled as a packed 2-byte array rather than an u16 because (a) it is not native endian and (b) its alignment is not necessary 2 bytes (it's actually 1).
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(C, packed)]
pub struct NetworkEndianU16([u8; 2]);

impl PartialOrd for NetworkEndianU16
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Rhs) -> Option<Ordering>
	{
		u16::from_be(u16::from_bytes(self.0)).partial_cmp(u16::from_be(u16::from_bytes(other.0)))
	}
}

impl Ord for NetworkEndianU16
{
	#[inline(always)]
	fn cmp(&self, other: &Rhs) -> Ordering
	{
		u16::from_be(u16::from_bytes(self.0)).cmp(u16::from_be(u16::from_bytes(other.0)))
	}
}

impl NetworkEndian for NetworkEndianU16
{
	#[inline(always)]
	fn bytes(&self) -> &[u8]
	{
		&self.0[..]
	}
}

impl NetworkEndianU16
{
	pub(crate) const Zero: Self = NetworkEndianU16([0, 0]);
	
	pub(crate) const Maximum: Self = NetworkEndianU16([0xFF, 0xFF]);
	
	#[inline(always)]
	pub(crate) const fn from_network_endian(network_endian: [u8; 2]) -> Self
	{
		NetworkEndianU16(network_endian)
	}
	
	#[inline(always)]
	pub(crate) fn to_native_endian(self) -> u16
	{
		u16::from_be(self.big_endian_from_bytes())
	}
	
	#[inline(always)]
	pub fn from_native_endian(native_endian: u16) -> Self
	{
		NetworkEndianU16(native_endian.to_be().to_bytes())
	}
	
	#[inline(always)]
	pub(crate) fn is_not_zero(self) -> bool
	{
		self.big_endian_from_bytes() != 0
	}
	
	#[inline(always)]
	fn big_endian_from_bytes(self) -> u16
	{
		u16::from_bytes(self.0)
	}
}
