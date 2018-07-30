// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Processing Incoming Segments 4.7.2.
macro_rules! processing_incoming_segments_4_7_2_ignore_the_segment_text
{
	($self: ident) =>
	{
		if $self.has_data()
		{
			let SEG = $self;
			invalid!(SEG, "TCP segment has payload in CloseWait, Closing, LastAcknowledgment or TimeWait state")
		}
	}
}
