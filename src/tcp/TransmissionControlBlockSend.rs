// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct TransmissionControlBlockSend
{
	/// RFC 793, page 25: "Oldest unacknowledged sequence number".
	///
	/// RFC 793, Glossary, page 81, expands this to call it the 'left sequence': "This is the next sequence number to be acknowledged by the data receiving TCP (or the lowest currently unacknowledged sequence number) and is sometimes referred to as the left edge of the send window".
	pub(crate) UNA: WrappingSequenceNumber,
	
	/// RFC 793, page 25: "Next sequence number to be sent".
	///
	/// RFC 793, Glossary, page 83, expands this to call it the 'send sequence': "This is the next sequence number the local (sending) TCP will use on the connection.
	/// It is initially selected from an initial sequence number curve (ISN) and is incremented for each octet of data or sequenced control transmitted".
	///
	/// RFC 4015 Section 1.1 Paragraph 3: "SND.NXT holds the segment sequence number of the next segment the TCP sender will (re-)transmit ... we define as 'SND.MAX' the segment sequence number of the next original transmit to be sent
	///
	/// The definition of SND.MAX is equivalent to the definition of 'snd_max' in [Wright, G. R. and W. R. Stevens, TCP/IP Illustrated, Volume 2 (The Implementation), Addison Wesley, January 1995]()".
	///
	/// It is worth noting that our definition of `SND.NXT` is actually the definition of `snd_max` in FreeBSD (and the above book).
	pub(crate) NXT: WrappingSequenceNumber,
	
	/// RFC 793, Glossary, page 83 expands this to call it the 'send window': "This represents the sequence numbers which the remote (receiving) TCP is willing to receive.
	/// It is the value of the window field specified in segments from the remote (data receiving) TCP.
	/// The range of new sequence numbers which may be emitted by a TCP lies between SND.NXT and SND.UNA + SND.WND - 1.
	/// (Retransmissions of sequence numbers between SND.UNA and SND.NXT are expected, of course)".
	///
	/// As of RFC 7323, Section 2.2 this is now the value left-shifted by `Snd.Wind.Shift` bits.
	pub(crate) WND: WindowSize,

	/// RFC 1323, Section 2, page 10: "The connection state is augmented by two window shift counts, Snd.Wind.Shift and Rcv.Wind.Shift, to be applied to the incoming and outgoing window fields, respectively."
	pub(crate) Wind: Wind,
	
	/// RFC 793, Page 19: "segment sequence number used for last window update".
	///
	/// RFC 793, Page 72: "SND.WL1 records the sequence number of the last segment used to update SND.WND".
	///
	/// RFC 793, Glossary, Page 83: "segment sequence number at last window update".
	pub(crate) WL1: WrappingSequenceNumber,
	
	/// RFC 793, Page 19: "segment acknowledgment number used for last window update".
	///
	/// RFC 793, Page 72: "SND.WL2 records the acknowledgment number of the last segment used to update SND.WND".
	///
	/// RFC 793, Glossary, Page 83: "segment acknowledgment number at last window update".
	pub(crate) WL2: WrappingSequenceNumber,
}
