// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// See RFC 5961 Section 5.2.
#[derive(Debug)]
pub(crate) struct TransmissionControlBlockMaximaSend
{
	/// RFC 5961 Section 5.2: "A new state variable MAX.SND.WND is defined as the largest window that the local sender has ever received from its peer.
	/// This window may be scaled to a value larger than 65,535 bytes".
	pub(crate) WND: WindowSize,
}
