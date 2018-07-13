// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// An RFC 1071 compliant check sum calculation.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct Rfc1141CompliantCheckSum(u16);

impl From<u16> for Rfc1141CompliantCheckSum
{
	#[inline(always)]
	fn from(check_sum: u16) -> Self
	{
		Rfc1141CompliantCheckSum(check_sum)
	}
}

impl Into<u16> for Rfc1141CompliantCheckSum
{
	#[inline(always)]
	fn into(self) -> u16
	{
		self.0
	}
}

impl Into<u32> for Rfc1141CompliantCheckSum
{
	#[inline(always)]
	fn into(self) -> u32
	{
		self.0 as u32
	}
}

impl From<NetworkEndianU16> for Rfc1141CompliantCheckSum
{
	#[inline(always)]
	fn from(check_sum: NetworkEndianU16) -> Self
	{
		Rfc1141CompliantCheckSum(check_sum.to_native_endian())
	}
}

impl Into<NetworkEndianU16> for Rfc1141CompliantCheckSum
{
	#[inline(always)]
	fn into(self) -> NetworkEndianU16
	{
		NetworkEndianU16::from_native_endian(self.0)
	}
}

impl Rfc1141CompliantCheckSum
{
	const Zero: Self = Rfc1141CompliantCheckSum(0);
	
	#[inline(always)]
	pub(crate) fn validates(self) -> bool
	{
		self.0 == Self::Zero.0
	}
	
	#[inline(always)]
	pub(crate) fn to_network_endian(self) -> NetworkEndianU16
	{
		NetworkEndianU16::from_native_endian(self.0)
	}
	
	#[inline(always)]
	pub(crate) fn internet_protocol_version_4_tcp_check_sum(source_internet_protocol_version_4_address: &NetworkEndianU32, destination_internet_protocol_version_4_address: &NetworkEndianU32, internet_packet_payload_pointer: NonNull<u8>, layer_4_packet_size: usize) -> Self
	{
		Self::internet_protocol_version_4_layer_4_check_sum(source_internet_protocol_version_4_address, destination_internet_protocol_version_4_address, internet_packet_payload_pointer, layer_4_packet_size, TcpLayer4ProtocolNumber)
	}

	#[inline(always)]
	pub(crate) fn internet_protocol_version_4_layer_4_check_sum(source_internet_protocol_version_4_address: &NetworkEndianU32, destination_internet_protocol_version_4_address: &NetworkEndianU32, internet_packet_payload_pointer: NonNull<u8>, layer_4_packet_size: usize, layer_4_protocol_number: u8) -> Self
	{
		let sum = Self::internet_protocol_version_4_pseudo_header_check_sum_partial(source_internet_protocol_version_4_address, destination_internet_protocol_version_4_address, layer_4_packet_size, layer_4_protocol_number);
		let sum = Self::from_data_check_sum_partial(internet_packet_payload_pointer, layer_4_packet_size, sum);
		Self::finalize(sum)
	}
	
	#[inline(always)]
	fn internet_protocol_version_4_pseudo_header_check_sum_partial(source_internet_protocol_version_4_address: &NetworkEndianU32, destination_internet_protocol_version_4_address: &NetworkEndianU32, layer_4_packet_size: usize, layer_4_protocol_number: u8) -> u32
	{
		let pseudo_header = NetworkEndianU32::psuedo_header(source_internet_protocol_version_4_address, destination_internet_protocol_version_4_address, layer_4_protocol_number, layer_4_packet_size);
		
		Self::from_struct_check_sum_partial(&pseudo_header, 0)
	}
	
	#[inline(always)]
	pub(crate) fn internet_protocol_version_6_tcp_check_sum(source_internet_protocol_version_6_address: &NetworkEndianU128, destination_internet_protocol_version_6_address: &NetworkEndianU128, internet_packet_payload_pointer: NonNull<u8>, layer_4_packet_size: usize) -> Self
	{
		Self::internet_protocol_version_6_layer_4_check_sum(source_internet_protocol_version_6_address, destination_internet_protocol_version_6_address, internet_packet_payload_pointer, layer_4_packet_size, TcpLayer4ProtocolNumber)
	}
	
	#[inline(always)]
	pub(crate) fn internet_protocol_version_6_layer_4_check_sum(source_internet_protocol_version_6_address: &NetworkEndianU128, destination_internet_protocol_version_6_address: &NetworkEndianU128, internet_packet_payload_pointer: NonNull<u8>, layer_4_packet_size: usize, layer_4_protocol_number: u8) -> Self
	{
		let sum = Self::internet_protocol_version_6_pseudo_header_check_sum_partial(source_internet_protocol_version_6_address, destination_internet_protocol_version_6_address, layer_4_packet_size, layer_4_protocol_number);
		let sum = Self::from_data_check_sum_partial(internet_packet_payload_pointer, layer_4_packet_size, sum);
		Self::finalize(sum)
	}
	
	#[inline(always)]
	fn internet_protocol_version_6_pseudo_header_check_sum_partial(source_internet_protocol_version_6_address: &NetworkEndianU128, destination_internet_protocol_version_6_address: &NetworkEndianU128, layer_4_packet_size: usize, layer_4_protocol_number: u8) -> u32
	{
		let pseudo_header = NetworkEndianU128::psuedo_header(source_internet_protocol_version_6_address, destination_internet_protocol_version_6_address, layer_4_protocol_number, layer_4_packet_size);
		
		Self::from_struct_check_sum_partial(&pseudo_header, 0)
	}
	
	#[inline(always)]
	fn from_struct_check_sum_partial<T>(data: &T, initial_value: u32) -> u32
	{
		let data_pointer = unsafe { NonNull::new_unchecked(data as *const T as *const u8 as *mut u8) };
		let data_length = size_of::<T>();
		Self::from_data_check_sum_partial(data_pointer, data_length, initial_value)
	}
	
	#[inline(always)]
	fn from_data_check_sum_partial(data_pointer: NonNull<u8>, data_length: usize, initial_value: u32) -> u32
	{
		#[inline(always)]
		fn accumulate_u16_chunks(mut data_pointer: usize, even_data_length: usize, initial_value: u32) -> (u32, usize)
		{
			let maximum_pointer = data_pointer + even_data_length;
			let mut sum = initial_value;
			
			while data_pointer < maximum_pointer
			{
				const SizeOfU16: usize = size_of::<u16>();
				
				let data_chunk = u16::from_be(unsafe { *(data_pointer as *mut u16) });
				let word = data_chunk as u32;
				sum += word;
				data_pointer += SizeOfU16;
			}
			
			(sum, data_pointer)
		}
		
		let data_pointer = data_pointer.as_ptr() as usize;
		
		let uneven = (data_length & 0b0000_0001) != 0;
		let sum = if uneven
		{
			let (sum, uneven_data_pointer) = accumulate_u16_chunks(data_pointer, data_length - 1, initial_value);
			
			let uneven_final_byte = (unsafe { *((uneven_data_pointer + 1) as *mut u8) }) as u16;
			let word = (uneven_final_byte << 8) as u32;
			
			sum + word
		}
		else
		{
			accumulate_u16_chunks(data_pointer, data_length, initial_value).0
		};
		
		sum
	}
	
	#[inline(always)]
	fn finalize(mut sum: u32) -> Self
	{
		while (sum >> 16) != 0
		{
			sum = (sum & 0x0000FFFF) + (sum >> 16);
		}
		
		Rfc1141CompliantCheckSum((!sum) as u16)
	}
}
