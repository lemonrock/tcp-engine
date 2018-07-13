// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Pre-shared secret keys for authenticating TCP segments using the (obsolete but widely deployed) MD5 option and the newer authentication option schemes.
///
/// * If a connection does not supply an authenticated segment for which a pre-shared secret key is known, then the segment is discarded.
/// * If a connection supplies an authenticated segment which does not validate, then the segment is discarded.
/// * A connection can not switch authentication type (MD5, HMAC-SHA1, etc).
/// * A connection can not switch keys.
#[derive(Debug, Clone)]
pub struct AuthenticationPreSharedSecretKeys<Address: InternetProtocolAddress>
{
	md5: HashMap<Md5AuthenticationConnectionIdentifier<Address>, Rc<Md5PreSharedSecretKey>>,
}

impl<Address: InternetProtocolAddress> AuthenticationPreSharedSecretKeys<Address>
{
	/// Creates a new instance.
	#[inline(always)]
	pub fn new(md5: HashMap<Md5AuthenticationConnectionIdentifier<Address>, Rc<Md5PreSharedSecretKey>>) -> Self
	{
		Self
		{
			md5
		}
	}
	
	/// Is authentication required for this connection?
	#[inline(always)]
	pub fn authentication_is_required(&self, remote_internet_protocol_address: &Address, local_port: NetworkEndianU16) -> bool
	{
		self.md5.contains_key(&Md5AuthenticationConnectionIdentifier::new(*remote_internet_protocol_address, local_port))
	}
	
	/// Find a MD5 authentication key.
	#[inline(always)]
	pub fn find_md5_authentication_key(&self, remote_internet_protocol_address: &Address, local_port: NetworkEndianU16) -> Option<Rc<Md5PreSharedSecretKey>>
	{
		self.md5.get(&Md5AuthenticationConnectionIdentifier::new(*remote_internet_protocol_address, local_port)).map(|key| key.clone())
	}
}
