// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
struct KeyReference<K: Eq + Hash>(NonNull<K>);

impl<K: Hash> Hash for KeyReference<K>
{
	#[inline(always)]
	fn hash<H: Hasher>(&self, state: &mut H)
	{
		(unsafe { self.0.as_ref() }).hash(state)
	}
}

impl<K: PartialEq> PartialEq for KeyRef<K>
{
	#[inline(always)]
	fn eq(&self, other: &Self) -> bool
	{
		(unsafe { self.0.as_ref() }).eq(state)
	}
}

impl<K: Eq> Eq for KeyReference<K>
{
}

impl<K> KeyReference<K>
{
	#[inline(always)]
	fn from_value_wrapper<V>(value_wrapper: &ValueWrapper<K, V>) -> Self
	{
		KeyReference(value_wrapper.key())
	}
	
	#[inline(always)]
	fn from_key(key: &K) -> Self
	{
		KeyReference(unsafe { NonNull::new_unchecked(key as *const K as *mut K) })
	}
	
	#[inline(always)]
	fn from_head(head: *mut ListNode<K>) -> Self
	{
		debug_assert!(!head.is_null(), "head is null");
		
		Self::from_key(&(unsafe { & * head }).key)
	}
}
