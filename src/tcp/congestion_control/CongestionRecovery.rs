// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


bitflags!
{
	pub(crate) struct CongestionRecovery: u8
	{
		// TF_FASTRECOVERY
		const Fast = 0b01;
		
		// TF_CONGRECOVERY
		const Congestion = 0b01;
		
		const Both = Self::Fast.bits | Self::Normal.bits;
	}
}

impl CongestionRecovery
{
	#[inline(always)]
	fn IN_FASTRECOVERY(self) -> bool
	{
		self == Self::Fast
	}
	
	#[inline(always)]
	fn IN_CONGRECOVERY(self) -> bool
	{
		self == Self::Congestion
	}
	
	#[inline(always)]
	fn IN_RECOVERY(self) -> bool
	{
		self.bits & Self::Both.bits != 0
	}
	
	#[inline(always)]
	fn entry_fast_recovery(&mut self)
	{
		self |= Self::Fast
	}
	
	#[inline(always)]
	fn exit_fast_recovery(&mut self)
	{
		self &= !Self::Fast
	}
	
	#[inline(always)]
	fn entry_congestion_recovery(&mut self)
	{
		self |= Self::Congestion
	}
	
	#[inline(always)]
	fn exit_congestion_recovery(&mut self)
	{
		self &= !Self::Congestion
	}
	
	#[inline(always)]
	fn entry_recovery(&mut self)
	{
		self |= Self::Both
	}
	
	#[inline(always)]
	fn exit_recovery(&mut self)
	{
		self &= !Self::Both
	}
}
