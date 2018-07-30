// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct SipHashKey
{
	key_part_0: Cell<u64>,
	key_part_1: Cell<u64>,
}

impl Default for SipHashKey
{
	#[inline(always)]
	fn default() -> Self
	{
		Self::new_random()
	}
}

impl SipHashKey
{
	#[inline(always)]
	pub(crate) fn new_random() -> Self
	{
		Self
		{
			key_part_0: Cell::new(generate_hyper_thread_safe_random_u64()),
			key_part_1: Cell::new(generate_hyper_thread_safe_random_u64()),
		}
	}
	
	#[inline(always)]
	pub(crate) fn regenerate(&self)
	{
		self.key_part_0.set(generate_hyper_thread_safe_random_u64());
		self.key_part_1.set(generate_hyper_thread_safe_random_u64());
	}
	
	#[inline(always)]
	pub(crate) fn new_hasher(&self) -> SipHasher24
	{
		SipHasher24::new_with_keys(self.key_part_0.get(), self.key_part_1.get())
	}
}
