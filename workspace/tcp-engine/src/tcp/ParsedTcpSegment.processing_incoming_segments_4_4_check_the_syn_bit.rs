// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Processing Incoming Segments 4.4: Check the SYN bit.
macro_rules! processing_incoming_segments_4_4_check_the_syn_bit
{
	($self: ident, $transmission_control_block: ident) =>
	{
		if $self.synchronize_flag_set()
		{
			// RFC 5961 Section 4.2: "... handling of the SYN in the synchronized state SHOULD be performed as follows:
			// If the SYN bit is set, irrespective of the sequence number, TCP MUST send an ACK (also referred to as challenge ACK) to the remote peer <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>.
			// After sending the acknowledgment, TCP MUST drop the unacceptable segment and stop processing further".
			//
			// This diverges from RFC 793 / Processing Incoming Segments 4.4.2.
			$self.interface.send_challenge_acknowledgment($self.reuse_packet(), $transmission_control_block, $self.now);
			return
		}
	}
}
