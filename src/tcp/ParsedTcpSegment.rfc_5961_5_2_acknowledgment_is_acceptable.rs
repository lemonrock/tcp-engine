// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


macro_rules! rfc_5961_5_2_acknowledgment_is_acceptable
{
    ($self: ident, $transmission_control_block: ident) =>
    {
        {
        	let SND = &$transmission_control_block.SND;
        	let MAX = &$transmission_control_block.MAX;
        	let SEG = $self.SEG;
        	
        	if unlikely(SND.NXT.sequence_numbers_differ_by_too_much(SEG.ACK))
        	{
				$self.interface.send_challenge_acknowledgment($self.reuse_packet(), $transmission_control_block, $self.now);
        		return;
        	}
        	
			// RFC 5961 Section 5.2 Paragraph 1: "The ACK value is considered acceptable only if it is in the range of ((SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT)
			// All incoming segments whose ACK value doesn't satisfy the above condition MUST be discarded and an ACK sent back".
			if !((SND.UNA - MAX.SND.WND) <= SEG.ACK && SEG.ACK <= SND.NXT)
			{
				$self.interface.send_challenge_acknowledgment($self.reuse_packet(), $transmission_control_block, $self.now);
				return;
			}
        }
    }
}
