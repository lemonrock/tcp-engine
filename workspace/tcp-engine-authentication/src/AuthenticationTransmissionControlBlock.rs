// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Authentication methods for a transmission control block.
pub trait AuthenticationTransmissionControlBlock
{
	#[doc(hidden)]
	#[inline(always)]
	fn md5_authentication_key(&self) -> Option<&Rc<Md5PreSharedSecretKey>>;
	
	#[doc(hidden)]
	#[inline(always)]
	fn authentication_is_required(&self) -> bool;
}
