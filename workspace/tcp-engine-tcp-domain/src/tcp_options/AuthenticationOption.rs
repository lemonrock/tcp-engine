// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Authentication Option.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(C, packed)]
pub struct AuthenticationOption(pub Authentication);

impl AuthenticationOption
{
	#[doc(hidden)]
	pub const Kind: u8 = 29;
	
	#[doc(hidden)]
	pub const Md5SignatureOptionKind: u8 = 19;
	
	#[doc(hidden)]
	pub const Md5SignatureOptionKnownLength: usize = 18;
}
