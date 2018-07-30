// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Provides recent connection data for this connection.
pub trait RecentConnectionDataProvider<Address: InternetProtocolAddress>: ConnectionIdentification<Address>
{
	/// Provides recent connection data for this connection.
	#[inline(always)]
	fn recent_connection_data(&self) -> RecentConnectionData;
}
