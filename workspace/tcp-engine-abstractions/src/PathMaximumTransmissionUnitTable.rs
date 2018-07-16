// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Represent a table (probably similar to a routing table) of Path Maximum Transmission Unit values.
pub trait PathMaximumTransmissionUnitTable<Address: InternetProtocolAddress>
{
	/// Used specifically when setting TCP maximum segment size option.
	///
	/// Intended to be implemented as a combination of a cache of `PathMTU` and a set of known, fixed values, perhaps implemented using a routing table such as `IpLookupTable` (in the crate `treebitmap`).
	///
	/// A suitable cache is `LeastRecentlyUsedCacheWithExpiry`.
	///
	/// If there is no specific entry in the cache, an implementation can use `Address::DefaultPathMaximumTransmissionUnitSize`.
	///
	/// Note also the advice of RFC 2923 Section 2.3: "The MSS should be determined based on the MTUs of the interfaces on the system".
	#[inline(always)]
	fn current_path_maximum_transmission_unit(&self, remote_internet_protocol_address: &Address) -> u16;
}
