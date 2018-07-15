// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// This design uses a variant of RFC 6528 Section 3.
///
/// In this variant:-
///
/// * the value `M` has a random offset applied.
/// * the secret key is 256 bits.
pub struct InitialSequenceNumberGenerator
{
	secret_key: [u8; 256 / 8]
}

impl Default for InitialSequenceNumberGenerator
{
	#[inline(always)]
	fn default() -> Self
	{
		Self
		{
			secret_key: unsafe
			{
				let secret_key_u64: [u64; 4] =
				[
					generate_hyper_thread_safe_random_u64(),
					generate_hyper_thread_safe_random_u64(),
					generate_hyper_thread_safe_random_u64(),
					generate_hyper_thread_safe_random_u64(),
				];
				transmute(secret_key_u64)
			},
		}
	}
}

impl InitialSequenceNumberGenerator
{
	/// Generate in an initial sequence number.
	#[allow(non_snake_case)]
	#[inline(always)]
	pub fn generate_initial_sequence_number<Address: InternetProtocolAddress>(&self, local_address: &Address, remote_address: &Address, remote_port_local_port: RemotePortLocalPort) -> WrappingSequenceNumber
	{
		let M = Self::M();
		let F = self.F(local_address, remote_address, remote_port_local_port);
		WrappingSequenceNumber::from(M.wrapping_add(F) as u32)
	}
	
	#[allow(non_snake_case)]
	#[inline(always)]
	fn M() -> u64
	{
		const FourMicrosecondTick: u64 = 4;
		
		let rfc_6528_M = MonotonicMillisecondTimestamp::microseconds_since_boot() / FourMicrosecondTick;
		
		rfc_6528_M + Self::random_offset()
	}
	
	#[allow(non_snake_case)]
	#[inline(always)]
	fn F<Address: InternetProtocolAddress>(&self, local_address: &Address, remote_address: &Address, remote_port_local_port: RemotePortLocalPort) -> u64
	{
		let mut hasher = Sha256::default();
		
		hasher.input(local_address.bytes());
		hasher.input(remote_port_local_port.local_port().bytes());
		hasher.input(remote_address.bytes());
		hasher.input(remote_port_local_port.remote_port().bytes());
		hasher.input(&self.secret_key);
		
		let digest = hasher.result();
		
		Self::xor_digest_bytes_to_8_bytes(&digest[..])
	}
	
	#[inline(always)]
	fn xor_digest_bytes_to_8_bytes(digest: &[u8]) -> u64
	{
		type BytesPointer = *const u64;
		const BytesPerU64: usize = size_of::<u64>();
		
		let pointer_to_start = digest.as_ptr() as usize;
		let pointer_to_end = pointer_to_start + digest.len();
		
		let mut xor_ed_digest = 0;
		let mut pointer_to_next_u64 = pointer_to_start;
		while pointer_to_next_u64 != pointer_to_end
		{
			xor_ed_digest ^= unsafe { * (pointer_to_next_u64 as BytesPointer) };
			pointer_to_next_u64 += BytesPerU64;
		}
		
		xor_ed_digest
	}
	
	#[inline(always)]
	fn random_offset() -> u64
	{
		const Increment: u64 = 1 << 12;
		const RandomIncrementMask: u64 = Increment - 1;
		
		generate_hyper_thread_safe_random_u64() & RandomIncrementMask
	}
}
