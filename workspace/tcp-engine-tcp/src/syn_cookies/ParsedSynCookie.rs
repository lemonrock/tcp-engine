// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A SYN cookie.
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct ParsedSynCookie
{
	/// RFC 793, Glossary, Page 80: "The Initial Receive Sequence number.
	/// The first sequence number used by the sender on a connection".
	pub IRS: WrappingSequenceNumber,
	
	/// RFC 793, Glossary, Page 80: "The Initial Send Sequence number.
	/// The first sequence number used by the sender on a connection".
	#[allow(non_snake_case)]
	pub ISS: WrappingSequenceNumber,
	
	/// RFC 793: "If this option is present, then it communicates the maximum receive segment size at the TCP which sends this segment".
	pub their_maximum_segment_size: u16,
	
	/// Their window scale option.
	pub their_window_scale: Option<u8>,
	
	/// Their 'selective acknowledgments permitted' option.
	pub their_selective_acknowledgment_permitted: bool,
	
	/// Their 'explicit congestion notification' supported option.
	pub explicit_congestion_notification_supported: bool,
}
