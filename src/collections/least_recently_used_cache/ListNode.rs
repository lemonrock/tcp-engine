// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
struct ListNode<K>
{
	key: K,
	next: *mut Self,
	previous: *mut Self,
}

impl<K> ListNode<K>
{
	#[inline(always)]
	fn key(&self) -> NonNull<K>
	{
		unsafe { NonNull::new_unchecked((&self.key) as *const _ as *mut _) }
	}
	
	#[inline(always)]
	fn remove_as_head_from_linked_list(&mut self, linked_list: &mut LinkedList<K>) -> NonNull<K>
	{
		debug_assert!(self.previous.is_null(), "self.previous should be null for a head list node");
		
		let next = self.next;
		
		linked_list.head = if likely(!next.is_null())
		{
			debug_assert_ne!(next, self as *mut Self, "self.next is self");
			
			(unsafe { &mut *next }).previous = null_mut();
			
			next
		}
		else
		{
			null_mut()
		};
		unsafe { NonNull::new_unchecked(&mut self.key) }
	}
	
	#[inline(always)]
	fn move_to_tail(&mut self, linked_list: &mut LinkedList<K>)
	{
		if likely(linked_list.tail != value.list_node)
		{
			self.remove_from_linked_list(&mut linked_list);
			self.insert_at_tail(&mut linked_list);
		}
	}
	
	#[inline(always)]
	fn remove_from_linked_list(&mut self, linked_list: &mut LinkedList<K>)
	{
		let previous = self.previous;
		let next = self.next;
		
		if !previous.is_null()
		{
			debug_assert_ne!(previous, self as *mut Self, "self.previous is self");
			
			let previous = unsafe { &mut *previous };
			previous.next = next;
		}
		
		if !next.is_null()
		{
			debug_assert_ne!(next, self as *mut Self, "self.next is self");
			
			(unsafe { &mut * next }).previous = previous;
		}
	}
	
	#[inline(always)]
	fn insert_at_head(&mut self, linked_list: &mut LinkedList<K>)
	{
		let old_head = linked_list.head;
		if unlikely(old_head.is_null())
		{
			debug_assert!(linked_list.tail.is_null(), "If linked_list.head is null then linked_list.tail must be null");
			
			self.previous = null_mut();
			self.next = null_mut();
			
			linked_list.tail = self;
		}
		else
		{
			self.next = old_head;
			self.previous = null_mut();
			
			let old_head = (unsafe { &mut *old_head });
			old_head.previous = self;
		}
		
		linked_list.head = self;
	}
	
	#[inline(always)]
	fn insert_at_tail(&mut self, linked_list: &mut LinkedList<K>)
	{
		let old_tail = linked_list.tail;
		if unlikely(old_tail.is_null())
		{
			debug_assert!(linked_list.head.is_null(), "If linked_list.tail is null then linked_list.head must be null");
			
			self.previous = null_mut();
			self.next = null_mut();
			
			linked_list.head = self;
		}
		else
		{
			debug_assert!(!linked_list.head.is_null(), "If linked_list.tail is not null then linked_list.head must be not null");
			
			self.previous = old_tail;
			self.next = null_mut();
			
			(unsafe { &mut * old_tail }).next = self;
		}
		
		linked_list.tail = self;
	}
	
	#[inline(always)]
	fn insert_at_tail_newly_created(&mut self, linked_list: &mut LinkedList<K>, old_tail: *mut Self) -> NonNull<Self>
	{
		if unlikely(old_tail.is_null())
		{
			debug_assert!(linked_list.head.is_null(), "If linked_list.tail is null then linked_list.head must be null");
			
			linked_list.head = self;
		}
		else
		{
			debug_assert!(!linked_list.head.is_null(), "If linked_list.tail is not null then linked_list.head must be not null");
			
			(unsafe { &mut * old_tail }).next = self;
		}
		
		linked_list.tail = self;
		
		unsafe { NonNull::new_unchecked(list_node_mut_ref as *mut ListNode<K>) }
	}
}
