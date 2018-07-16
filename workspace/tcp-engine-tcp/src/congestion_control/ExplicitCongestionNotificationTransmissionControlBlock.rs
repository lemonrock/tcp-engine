// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Explicit congestion notification (ECN) behaviour for a Transmission Control Block.
pub trait ExplicitCongestionNotificationTransmissionControlBlock: CongestionControlTransmissionControlBlock + StateTransmissionControlBlock
{
	/// Is explicit congestion notification supported for this connection?
	#[inline(always)]
	fn explicit_congestion_notification_supported(&self) -> bool
	{
		self.congestion_control_reference().explicit_congestion_notification_state.is_some()
	}
	
	/// Is explicit congestion notification unsupported for this connection?
	#[inline(always)]
	fn explicit_congestion_notification_unsupported(&self) -> bool
	{
		self.congestion_control_reference().explicit_congestion_notification_state.is_none()
	}
	
	/// Adds the flag Explicit Congestion Echo (ECE) to acknowledgments if the explicit congestion notification state requires it.
	#[inline(always)]
	fn add_explicit_congestion_echo_flag_to_acknowledgment_if_appropriate(&self, flags: Flags) -> Flags
	{
		if let Some(ref explicit_congestion_notification_state) = self.explicit_congestion_notification_state_reference()
		{
			if explicit_congestion_notification_state.acknowledgments_should_explicit_congestion_echo()
			{
				return flags | Flags::ExplicitCongestionEcho
			}
		}
		flags
	}
	
	/// Disables explicit congestion notification.
	///
	/// Can only be called in the state SynchronizeSent.
	#[inline(always)]
	fn disable_explicit_congestion_notification(&mut self)
	{
		self.congestion_control_mutable_reference().disable_explicit_congestion_notification()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn explicit_congestion_notification_state_reference(&self) -> Option<&ExplicitCongestionNotificationState>
	{
		self.congestion_control_reference().explicit_congestion_notification_state.as_ref()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn explicit_congestion_notification_state_mutable_reference(&mut self) -> Option<&mut ExplicitCongestionNotificationState>
	{
		self.congestion_control_mutable_reference().explicit_congestion_notification_state.as_mut()
	}
}
