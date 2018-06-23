// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// This design uses a variant of RFC 6526 Section 3.
///
/// In this variant:-
///
/// * the value `M` has a random offset applied.
/// * the secret key is 256 bits.
pub(crate) struct InitialSequenceNumberGenerator
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
	#[inline(always)]
	pub(crate) fn generate_initial_sequence_number<Address: InternetProtocolAddress>(&self, local_address: &Address, remote_address: &Address, remote_port_local_port: RemotePortLocalPort) -> WrappingSequenceNumber
	{
		let M = Self::M();
		let F = self.F(local_address, remote_address, remote_port_local_port);
		WrappingSequenceNumber(M.wrapping_add(F))
	}
	
	#[inline(always)]
	fn M()
	{
		const FourMicrosecondTick: u64 = 4;
		
		let rfc_6526_M = MonotonicMillisecondTimestamp::microseconds_since_boot() / FourMicrosecondTick;
		
		rfc_6526_M + Self::random_offset()
	}
	
	#[inline(always)]
	fn F<Address: InternetProtocolAddress>(&self, local_address: &Address, remote_address: &Address, remote_port_local_port: RemotePortLocalPort) -> u32
	{
		let mut hasher = Sha256::default();
		
		hasher.input(local_address.bytes());
		hasher.input(remote_port_local_port.local_port().bytes());
		hasher.input(remote_address.bytes());
		hasher.input(remote_port_local_port.remote_port().bytes());
		hasher.input(&self.secret_key);
		
		let sha_256_digest_u256 = hasher.result();
		
		const BytesInASha256Digest: usize = 256 / 8;
		const BytesPerU32: usize = size_of::<u32>();
		
		let mut pointer_to_next_u32 = sha_256_digest_u256.as_slice().as_ptr() as usize;
		
		let mut sha_256_digest_u32 = unsafe { * (pointer_to_next_u32 as *const u32) };
		pointer_to_next_u32 += BytesPerU32;
		
		let pointer_to_end = pointer_to_next_u32 + BytesInASha256Digest;
		while pointer_to_next_u32 != pointer_to_end
		{
			sha_256_digest_u32 ^= unsafe { * (pointer_to_next_u32 as *const u32) };
			pointer_to_next_u32 += BytesPerU32;
		}
		
		sha_256_digest_u32
	}
	
	#[inline(always)]
	fn random_offset() -> u64
	{
		const Increment: u64 = 1 << 12;
		const RandomIncrementMask: u64 = Increment - 1;
		
		generate_hyper_thread_safe_random_u64() & RandomIncrementMask
	}
}
