// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
struct LinkedList<K>
{
	head: *mut ListNode<K>,
	tail: *mut ListNode<K>,
}

impl<K> Default for LinkedList<K>
{
	#[inline(always)]
	fn default() -> Self
	{
		Self
		{
			head: null_mut(),
			tail: null_mut(),
		}
	}
}

impl<K> LinkedList<K>
{
	#[inline(always)]
	fn pop_head(&mut self) -> KeyReference<K>
	{
		debug_assert!(!self.head.is_null(), "head is null");
		
		KeyReference((unsafe { &mut * self.head }).remove_as_head_from_linked_list(self))
	}
}
