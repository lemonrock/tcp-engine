// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct TransmissionControlBlockReceive
{
	/// RFC 793, page 25: "Next sequence number expected on an incoming segments, and is the left or lower edge of the receive window."
	///
	/// RFC 793, Glossary, page 82, expands this to call it the 'receive next sequence number': "This is the next sequence number the local TCP is expecting to receive".
	pub(crate) NXT: WrappingSequenceNumber,
	
	/// RFC 793, Glossary, page 82, expands this to call it the 'receive window': "This represents the sequence numbers the local (receiving) TCP is willing to receive.
	/// Thus, the local TCP considers that segments overlapping the range RCV.NXT to RCV.NXT + RCV.WND - 1 carry acceptable data or control.
	/// Segments containing sequence numbers entirely outside of this range are considered duplicates and discarded".
	///
	/// As of RFC 1323, Section 2, page 10, this is now the value left-shifted by `Rcv.Wind.Shift` bits.
	pub(crate) WND: WindowSize,
	
	/// RFC 1323, Section 2, page 10: "The connection state is augmented by two window shift counts, Snd.Wind.Shift and Rcv.Wind.Shift, to be applied to the incoming and outgoing window fields, respectively."
	pub(crate) Wind: Wind,
	
	
	
	
	
	// TODO: ? what is rcv_processed ?
	pub(crate) processed: WrappingSequenceNumber,
}

impl TransmissionControlBlockReceive
{
	/// RFC 793, page 25: "Last sequence number expected on an incoming segment, and is the right or upper edge of the receive window".
	#[inline(always)]
	pub(crate) fn right_edge_of_the_receive_window(&self) -> WrappingSequenceNumber
	{
		let RCV = self;
		
		RCV.NXT + RCV.WND - 1
	}
}
