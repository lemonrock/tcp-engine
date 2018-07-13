// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


macro_rules! rfc_5961_5_2_acknowledgment_is_acceptable
{
    ($self: ident, $transmission_control_block: ident) =>
    {
        if unlikely($transmission_control_block.SND.rfc_5961_section_5_2_paragraph_1($self))
		{
			$self.interface.send_challenge_acknowledgment($self.reuse_packet(), $transmission_control_block, $self.now);
			return
		}
    }
}
