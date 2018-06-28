// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct LeastRecentlyUsedCache<K: Eq + Hash, V>
{
	map: BoundedHashMap<KeyReference<K>, ValueWrapper<V>>,
	head_is_least_recently_used: LinkedList<K>,
	pre_allocated_list_nodes: SlabAllocation<ListNode<K>>,
}

impl<K: Eq + Hash, V> LeastRecentlyUsedCache<K, V>
{
	#[inline(always)]
	pub(crate) fn new(maximum_capacity: usize) -> Self
	{
		Self
		{
			map: BoundedHashMap::new(maximum_capacity),
			head_is_least_recently_used: LinkedList::default(),
			pre_allocated_list_nodes: SlabAllocation::new(maximum_capacity),
		}
	}
	
	#[inline(always)]
	pub(crate) fn get(&mut self, key: &K) -> Option<&V>
	{
		match self.map.get_mut(key)
		{
			None => None,
			Some(value_wrapper) =>
			{
				value_wrapper.recently_used(&mut self.head_is_least_recently_used);
				Some(&value_wrapper.value)
			}
		}
	}
	
	#[inline(always)]
	pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V>
	{
		match self.map.get_mut(key)
		{
			None => None,
			Some(value_wrapper) =>
			{
				value_wrapper.recently_used(&mut self.head_is_least_recently_used);
				Some(&mut value_wrapper.value)
			}
		}
	}
	
	/// In the corner case of the cache being full and the key referencing a value already present, the least recently used item will be removed to make space even though this isn't strictly necessary.
	///
	/// This could be mitigated for by checking if the key is already present, but this requires two look ups which is expensive.
	#[inline(always)]
	pub(crate) fn insert(&mut self, key: K, value: V)
	{
		if unlikely(self.is_full())
		{
			self.remove_least_recently_used_if_full_to_make_space();
		}
		
		let mut value_wrapper = ValueWrapper
		{
			value,
			list_node: self.new_list_node(key),
		};
		
		let key_reference = KeyReference::from_value_wrapper(&value_wrapper);
		
		if let Some(old_value_wrapper) = self.map.insert(key_reference, value_wrapper)
		{
			self.clean_up_old_value(old_value_wrapper)
		}
	}
	
	#[inline(always)]
	fn remove(&mut self, key: &K)
	{
		if let Some((_key, old_value_wrapper)) = self.map.remove_entry(KeyReference::from_key(key))
		{
			self.clean_up_old_value(old_value_wrapper);
		}
	}
	
	#[inline(always)]
	fn remove_least_recently_used_if_full_to_make_space(&mut self)
	{
		debug_assert!(self.map.is_full(), "map and pre_allocated_list_nodes sizes not in lock step");
		
		let least_recently_used_key = self.head_is_least_recently_used.head;
		debug_assert!(!least_recently_used_key.is_null(), "head is null but the map and pre_allocated_list_nodes are full; this is only possible if the maximum_capacity is zero (0)");
		
		let (_key, old_value_wrapper) = self.map.remove_entry(KeyReference::from_head(least_recently_used_key)).unwrap();
		debug_assert!(!self.map.is_full(), "map is still full");
		
		self.clean_up_old_value(old_value_wrapper);
		debug_assert!(!self.is_full(), "pre_allocated_list_nodes is still full");
	}
	
	#[inline(always)]
	fn is_full(&mut self) -> bool
	{
		self.pre_allocated_list_nodes.is_full()
	}
	
	#[inline(always)]
	fn clean_up_old_value(&mut self, old_value_wrapper: ValueWrapper<V>)
	{
		let list_node = old_value_wrapper.list_node();
		list_node.remove_from_linked_list(&mut self.head_is_least_recently_used);
		
		drop(old_value_wrapper);
		self.pre_allocated_list_nodes.free_unchecked(list_node)
	}
	
	#[inline(always)]
	fn new_list_node(&mut self, key: K) -> NonNull<ListNode<K>>
	{
		let old_tail = self.head_is_least_recently_used.tail;
		let list_node_mut_ref = self.pre_allocated_list_nodes.allocate_unchecked
		(
			ListNode
			{
				key,
				next: null_mut(),
				previous: old_tail,
			}
		);
		list_node_mut_ref.insert_at_tail_newly_created(&mut self.head_is_least_recently_used, old_tail)
	}
}
