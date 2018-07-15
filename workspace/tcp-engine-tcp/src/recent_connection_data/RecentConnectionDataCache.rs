// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A cache of recent connections data to bootstrap new connections.
///
/// Typical uses are to ensure recently calculated retransmission time outs and congestion control information is used.
///
/// A maximum size is placed on the cache and a maximum duration for data within it.
///
/// An equivalent concept on FreeBSD is the 'hostcache'.
#[derive(Debug)]
pub struct RecentConnectionDataCache<Address: InternetProtocolAddress>
{
	cache: UnsafeCell<LeastRecentlyUsedCacheWithExpiry<Address, RecentConnectionData>>,
}

impl<Address: InternetProtocolAddress> RecentConnectionDataCache<Address>
{
	/// Creates a new instance.
	#[inline(always)]
	pub fn new(maximum_recent_connections_capacity: usize, expiry_period: MillisecondDuration) -> Self
	{
		Self
		{
			cache: UnsafeCell::new(LeastRecentlyUsedCacheWithExpiry::new(maximum_recent_connections_capacity, expiry_period)),
		}
	}
	
	/// Recent connection data or a default.
	///
	/// Borrowed value must be discarded before `update_recent_connection_data()` is called otherwise an undetectable borrow error will occur.
	#[inline(always)]
	pub fn get(&self, now: MonotonicMillisecondTimestamp, remote_internet_protocol_address: &Address) -> &RecentConnectionData
	{
		static Default: RecentConnectionData = RecentConnectionData::Default;
		
		self.cache().get(now, remote_internet_protocol_address).unwrap_or(&Default)
	}
	
	/// Update recent connection data.
	#[inline(always)]
	pub fn update(&self, transmission_control_block: &impl RecentConnectionDataProvider<Address>, now: MonotonicMillisecondTimestamp)
	{
		let remote_internet_protocol_address = transmission_control_block.remote_internet_protocol_address();
		let recent_connection_data = transmission_control_block.recent_connection_data();
		
		if let Some(cached_connection_data) = self.cache().get_mut(now, remote_internet_protocol_address)
		{
			cached_connection_data.update(recent_connection_data);
		}
		else
		{
			self.cache().insert(now, *remote_internet_protocol_address, recent_connection_data);
		}
	}
	
	#[inline(always)]
	fn cache(&self) -> &mut LeastRecentlyUsedCacheWithExpiry<Address, RecentConnectionData>
	{
		unsafe { &mut * self.cache.get() }
	}
}
