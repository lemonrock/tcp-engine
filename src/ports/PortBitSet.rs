// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Maximum number of ports: 2^16 = 65536.
///
/// Maximum number of u64: 65536 / 64 = 1024.
#[derive(Clone)]
pub struct PortBitSet([u64; PortBitSet::NumberOfElements]);

impl PortBitSet
{
	const BitsPerElementDivisionBitShift: usize = 6;
	
	const BitsPerElement: usize = 2^6;
	
	const BitsPerElementRemainderMask: usize = Self::BitsPerElement - 1;
	
	const NumberOfElements: usize = Self::divide_by_bits_per_element(2^16);
	
	const BytesPerElement: usize = Self::BitsPerElement / 8;
	
	/// Creates a new instance.
	#[inline(always)]
	pub fn empty() -> Self
	{
		unsafe { zeroed() }
	}
	
	/// Creates an instance with all ports bar those configured to be ignored (configuration features "server-drop-source-port-0", "server-drop-source-ports-1-1023" and "server-drop-source-ports-experimental-rfc-4727" (ports 1021 and 1022)).
	#[inline(always)]
	pub(crate) fn full_except_for_configured_remote_ports_to_drop() -> Self
	{
		let mut this = unsafe
		{
			let mut all_set: Self = uninitialized();
			(all_set.0.get_unchecked_mut(0) as *mut _ as *mut u64).write_bytes(0xFF, Self::NumberOfElements / Self::BytesPerElement);
			all_set
		};
		
		if cfg!(feature = "server-drop-source-port-0")
		{
			const TcpSourcePortZero: u16 = 0;
			this.remove(TcpSourcePortZero)
		}
		
		if cfg!(feature = "server-drop-source-ports-1-1023")
		{
			// Remove all but first bit.
			unsafe { *this.0.get_unchecked_mut(0) &= 0x01 };
			
			// Set port numbers 8 - 1023 inclusive to zero.
			let bytes_to_set_to_zero = 1024 / Self::BitsPerElement - 1;
			unsafe { (this.0.get_unchecked_mut(1) as *mut _ as *mut u64).write_bytes(0x00, bytes_to_set_to_zero) };
		}
		
		if cfg!(feature = "server-drop-source-ports-experimental-rfc-4727")
		{
			this.remove(1021);
			this.remove(1022);
		}
		
		this
	}
	
	/// RFC 6056: Section 3.2: "... ephemeral port selection algorithms should use the whole range 1024-65535".
	#[inline(always)]
	pub(crate) fn new_with_rfc_6056_ephemeral_ports_available() -> Self
	{
		let mut this = Self::new();
		unsafe { (this.0.get_unchecked_mut(0) as *mut _ as *mut u64).write_bytes(0xFF, 1024 / Self::BytesPerElement) };
		this
	}
	
	#[inline(always)]
	pub(crate) fn find_unused_securely_randomly(&self, inclusive_minimum_hint: u16) -> Option<u16>
	{
		// generate a random number between 0 and 65535; iterate with wrap-around until found.
		let random_initial_port_number = generate_hyper_thread_safe_random_u16();
		
		let initial_port_number = if random_initial_port_number < inclusive_minimum_hint
		{
			inclusive_minimum_hint
		}
		else
		{
			random_initial_port_number
		};
		
		let mut port_number = initial_port_number;
		while
		{
			if self.does_not_contain(port_number)
			{
				Some(port_number)
			}
			
			if port_number == ::std::u16::MAX
			{
				port_number = inclusive_minimum_hint
			}
			else
			{
				port_number += 1;
			}
			
			port_number != initial_port_number
		}
		{
		}
	}
	
	#[inline(always)]
	pub(crate) fn union(&self, other: &self) -> Self
	{
		let mut this: Self = unsafe { uninitialized() };
		
		for index in 0 .. Self::NumberOfElements
		{
			unsafe
			{
				*this.0.get_unchecked_mut(index) = set.0.get_unchecked(index) | other.0.get_unchecked(index)
			}
		}
		
		this
	}
	
	/// Does not contain port number?
	#[inline(always)]
	pub fn does_not_contain(&self, port_number: u16) -> bool
	{
		// Could be potentially replaced by the `_bittest64()` intrinsic, which is not part of Rust's support today.
		
		let (element, bit_in_element_mask) = Self::element_and_bit_in_element_mask(port_number);
		
		(unsafe { *self.0.get_unchecked(element) }) & bit_in_element_mask == 0
	}
	
	/// Contains port number?
	#[inline(always)]
	pub fn contains(&self, port_number: u16) -> bool
	{
		!self.does_not_contain(port_number)
	}
	
	/// Insert port number.
	#[inline(always)]
	pub fn insert(&mut self, port_number: u16)
	{
		let (element, bit_in_element_mask) = Self::element_and_bit_in_element_mask(port_number);
		
		unsafe { *self.0.get_unchecked_mut(element) |= bit_in_element_mask };
	}
	
	/// Remove port number.
	#[inline(always)]
	pub fn remove(&mut self, port_number: u16)
	{
		let (element, bit_in_element_mask) = Self::element_and_bit_in_element_mask(port_number);
		
		unsafe { *self.0.get_unchecked_mut(element) &= !bit_in_element_mask };
	}
	
	#[inline(always)]
	fn element_and_bit_in_element_mask(port_number: u16) -> (usize, u64)
	{
		let bit_number = port_number as usize;
		let element = Self::divide_by_bits_per_element(bit_number);
		let bit_in_element = Self::remainder_by_bits_per_element(bit_number);
		let bit_in_element_mask = 1 << bit_in_element;
		
		(element, bit_in_element_mask as u64)
	}
	
	#[inline(always)]
	const fn divide_by_bits_per_element(bit_number: usize) -> usize
	{
		// bit_number / Self::BitsPerElement
		bit_number >> Self::BitsPerElementDivisionBitShift
	}
	
	#[inline(always)]
	const fn remainder_by_bits_per_element(bit_number: usize) -> usize
	{
		// bit_number % Self::BitsPerElement
		bit_number & Self::BitsPerElementRemainderMask
	}
}

impl Index<u16> for PortBitSet
{
	type Output = bool;
	
	#[inline(always)]
	fn index(&self, port_number: u16) -> &bool
	{
		if self.contains(port_number)
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
