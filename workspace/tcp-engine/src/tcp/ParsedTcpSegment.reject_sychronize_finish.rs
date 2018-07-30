// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


macro_rules! reject_synchronize_finish
{
	($self: expr) =>
	{
		if $self.all_flags().contains(Flags::SynchronizeFinish)
		{
			let SEG = $self;
			invalid!(SEG, "Segments with the Synchronize and Finish flags both set were only valid in the historic T/TCP RFC 1644")
		}
	}
}
