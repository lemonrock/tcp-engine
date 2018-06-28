// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct BoundedHashMap<K: Hash + Eq, V>
{
	map: HashMap<K, V>,
	maximum_capacity_bound: usize,
}

impl<K: Hash + Eq, V> BoundedHashMap<K, V>
{
	#[inline(always)]
	pub(crate) fn new(maximum_capacity: usize) -> Self
	{
		let allocate_hash_map_with_slightly_more_capacity_as_insert_always_reserves_1 = maximum_capacity + 1;
		
		Self
		{
			map: HashMap::with_capacity(allocate_hash_map_with_slightly_more_capacity_as_insert_always_reserves_1),
			maximum_capacity_bound,
		}
	}
	
	#[inline(always)]
	pub(crate) fn contains_key(&self, key: &K) -> bool
	{
		self.map.contains_key(key)
	}
	
	#[inline(always)]
	pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V>
	{
		self.map.get_mut(key)
	}
	
	#[inline(always)]
	pub(crate) fn len(&self) -> usize
	{
		self.map.len()
	}
	
	#[inline(always)]
	pub(crate) fn is_full(&self) -> bool
	{
		self.len() == self.maximum_capacity_bound
	}
	
	#[inline(always)]
	pub(crate) fn is_over_filled(&self) -> bool
	{
		self.len() > self.maximum_capacity_bound
	}
	
	#[inline(always)]
	pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V>
	{
		self.map.insert(key, value)
	}
}
