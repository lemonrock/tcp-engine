// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum Authentication
{
	/// RFC 2385.
	Rfc2385ObsoleteMD5
	{
		digest: NonNull<[u8; 16]>,
	},
	
	/// The default scheme is HMAC-SHA1-96, known at IANA as `SHA1`.
	Rfc5926Authentication
	{
		key_id: u8,
		r_next_key_id: u8,
		// TCP Headers are 20 to 60 bytes long => 40 bytes of options.
		// This option takes 1 byte kind, 1 byte length, 1 byte key id and 1 byte r next key id, giving a maximum message_authentication_code of 36 bytes.
		message_authentication_code_length: u8,
		message_authentication_code: NonNull<u8>,
	}
}
