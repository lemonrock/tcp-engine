// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


macro_rules! adjust_comparison_for_wrap_around
{
	($us: ident, $them: ident, $less: block, $greater: block, $equal: block) =>
	{
		if $us > $them
		{
			if Self::difference_exceeds_wrap_around($us, $them)
			{
				$less
			}
			else
			{
				$greater
			}
		}
		else if $us < $them
		{
			if Self::difference_exceeds_wrap_around($them, $us)
			{
				$greater
			}
			else
			{
				$less
			}
		}
		else
		{
			$equal
		}
	}
}
