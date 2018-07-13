// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Kind of TCP authentication.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Authentication
{
	/// RFC 2385.
	Rfc2385ObsoleteMD5
	{
		/// Value of MD5 digest.
		digest: NonNull<[u8; 16]>,
	},
	
	/// The default scheme is HMAC-SHA1-96, known at IANA as `SHA1`.
	Rfc5925Authentication
	{
		/// Identifies the Master Key Tuple (MKT).
		///
		/// Value can be different for send and receive; each is in a separate 'namespace'.
		///
		/// We look up the master key tuple, then find the 'traffic' key for this direction.
		key_id: u8,
		
		/// The Master Key Tuple (MKT) that is ready at the sender to be used to authenticate received segments.
		///
		/// In other words, the key to use to to authenticate outgoing packets.
		r_next_key_id: u8,
		
		/// TCP Headers are 20 to 60 bytes long => 40 bytes of options.
		/// This option takes 1 byte kind, 1 byte length, 1 byte key id and 1 byte r next key id, giving a maximum message_authentication_code of 36 bytes.
		message_authentication_code_length: u8,
		
		/// Message authentication code.
		message_authentication_code: NonNull<u8>,
	}
}
