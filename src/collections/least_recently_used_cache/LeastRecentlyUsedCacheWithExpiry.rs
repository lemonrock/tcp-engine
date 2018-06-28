// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct LeastRecentlyUsedCacheWithExpiry<K: Eq + Hash, V>
{
	least_recently_used_cache: LeastRecentlyUsedCache<K, ExpiringValueWrapper<V>>,
	expiry_period: MillisecondDuration,
}

impl<K: Eq + Hash, V> LeastRecentlyUsedCacheWithExpiry<K, V>
{
	/// The `expiry_period` can be zero; entries are considered to be expired when this is exceeded.
	pub(crate) fn new(maximum_capacity: usize, expiry_period: MillisecondDuration) -> Self
	{
		Self
		{
			least_recently_used_cache: LeastRecentlyUsedCache::new(maximum_capacity),
			expiry_period
		}
	}
	
	#[inline(always)]
	pub(crate) fn get(&mut self, now: MonotonicMillisecondTimestamp, key: &K) -> Option<&V>
	{
		self.get_internal(now, key).map(|expiring_value_wrapper| &expiring_value_wrapper.value)
	}
	
	#[inline(always)]
	pub(crate) fn get_mut(&mut self, now: MonotonicMillisecondTimestamp, key: &K) -> Option<&mut V>
	{
		self.get_internal(now, key).map(|expiring_value_wrapper| &mut expiring_value_wrapper.value)
	}
	
	#[inline(always)]
	pub(crate) fn insert(&mut self, now: MonotonicMillisecondTimestamp, key: K, value: V)
	{
		self.least_recently_used_cache.insert(key, ExpiringValueWrapper
		{
			expires_at: now + self.expiry_period,
			value,
		})
	}
	
	#[inline(always)]
	fn get_internal(&mut self, now: MonotonicMillisecondTimestamp, key: &K) -> Option<&ExpiringValueWrapper<V>>
	{
		if let Some(expiring_value_wrapper) = self.least_recently_used_cache.get_mut(key)
		{
			if expiring_value_wrapper.has_expired()
			{
				self.least_recently_used_cache.remove(key);
				None
			}
			else
			{
				expiring_value_wrapper.recently_used(now, self.expiry_period);
				Some(expiring_value_wrapper)
			}
		}
		else
		{
			None
		}
	}
}
