// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
struct ExpiringValueWrapper<V>
{
	expires_at: MonotonicMillisecondTimestamp,
	value: V,
}

impl<V> ExpiringValueWrapper<V>
{
	#[inline(always)]
	fn has_expired(&self, now: MonotonicMillisecondTimestamp) -> bool
	{
		now > self.expires_at
	}
	
	#[inline(always)]
	fn recently_used(&mut self, now: MonotonicMillisecondTimestamp, expiry_period: MillisecondDuration)
	{
		self.expires_at = now + expiry_period;
	}
}