// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// State related information.
pub trait StateTransmissionControlBlock
{
	/// Is the state Established?
	#[inline(always)]
	fn is_state_established(&self) -> bool
	{
		self.state().is_established()
	}
	
	/// Is the state SynchronizeSent?
	#[inline(always)]
	fn is_state_synchronize_sent(&self) -> bool
	{
		self.state().is_synchronize_sent()
	}
	
	/// Is the state Synchronized?
	#[inline(always)]
	fn is_state_synchronized(&self) -> bool
	{
		self.state().is_synchronized()
	}
	
	/// Debug assert the state is SynchronizeSent.
	#[inline(always)]
	fn debug_assert_action_is_only_valid_in_sychronize_sent_state(&self)
	{
		debug_assert!(self.is_state_synchronize_sent(), "This can only be valid in the state SynchronizeSent");
	}
	
	/// Debug assert the state is one of the synchronized states.
	#[inline(always)]
	fn debug_assert_action_is_only_valid_in_synchronized_states(&self)
	{
		debug_assert!(self.is_state_synchronized(), "This can only be valid in the synchronized states");
	}
	
	/// Current state.
	#[inline(always)]
	fn state(&self) -> State
	{
		self.get_field_state()
	}
	
	/// Sets state.
	#[inline(always)]
	fn set_state(&mut self, state: State)
	{
		debug_assert!(state > self.state(), "new state '{:?}' does not advance from existing state '{:?}", state, self.state());
		
		self.set_field_state(state)
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn get_field_state(&self) -> State;
	
	#[doc(hidden)]
	#[inline(always)]
	fn set_field_state(&self, value: State);
}
