// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


trait DereferenceUnchecked
{
	type AB;
	
	type TCBA: TransmissionControlBlockAbstractions;
	
	#[inline(always)]
	fn is_not_null(self) -> bool;
	
	#[inline(always)]
	fn dereference_unchecked<'a>(self) -> &'a mut Alarm<Self::AB, Self::TCBA>;
}

impl<AB: AlarmBehaviour<TCBA>, TCBA: TransmissionControlBlockAbstractions> DereferenceUnchecked for *mut Alarm<AB, TCBA>
{
	type AB = AB;
	
	type TCBA = TCBA;
	
	#[inline(always)]
	fn is_not_null(self) -> bool
	{
		!self.is_null()
	}
	
	#[inline(always)]
	fn dereference_unchecked<'a>(self) -> &'a mut Alarm<Self::AB, Self::TCBA>
	{
		unsafe { &mut * self }
	}
}
