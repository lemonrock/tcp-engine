// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CachedCongestionData
{
	retransmission_time_out: RetransmissionTimeOut,
	ssthresh: u32,
	cwnd: u32,
	send_pipe: u32,
	receive_pipe: u32,
}

impl Default for CachedCongestionData
{
	#[inline(always)]
	fn default() -> Self
	{
		Self::Default
	}
}

impl CachedCongestionData
{
	const Default: Self = Self
	{
		retransmission_time_out: RetransmissionTimeOut::Default,
		ssthresh: 0,
		cwnd: 0,
		send_pipe: 0,
		receive_pipe: 0,
	};
	
	#[inline(always)]
	pub(crate) fn new(&self, retransmission_time_out: RetransmissionTimeOut, ssthresh: u32, cwnd: u32, send_pipe: u32, receive_pipe: u32) -> RetransmissionTimeOut
	{
		Self
		{
			retransmission_time_out,
			ssthresh,
			cwnd,
			send_pipe,
			receive_pipe,
		}
	}
	
	#[inline(always)]
	pub(crate) fn retransmission_time_out(&self) -> RetransmissionTimeOut
	{
		self.retransmission_time_out.clone()
	}
	
	#[inline(always)]
	pub(crate) fn update_retransmission_time_out(&mut self, retransmission_time_out: RetransmissionTimeOut)
	{
		self.retransmission_time_out.average_with(retransmission_time_out)
	}
	
	#[inline(always)]
	pub(crate) fn update_ssthresh(&mut self, ssthresh: u32)
	{
		if self.ssthresh == 0
		{
			self.ssthresh = ssthresh;
		}
		else
		{
			self.ssthresh = (self.ssthresh + ssthresh) / 2;
		}
	}
	
	#[inline(always)]
	pub(crate) fn update_cwnd(&mut self, cwnd: u32)
	{
		if self.cwnd == 0
		{
			self.cwnd = cwnd;
		}
		else
		{
			self.cwnd = (self.cwnd + cwnd) / 2;
		}
	}
	
	#[inline(always)]
	pub(crate) fn update_send_pipe(&mut self, send_pipe: u32)
	{
		if self.send_pipe == 0
		{
			self.send_pipe = send_pipe;
		}
		else
		{
			self.send_pipe = (self.send_pipe + send_pipe) / 2;
		}
	}
	
	#[inline(always)]
	pub(crate) fn update_receive_pipe(&mut self, receive_pipe: u32)
	{
		if self.receive_pipe == 0
		{
			self.receive_pipe = receive_pipe;
		}
		else
		{
			self.receive_pipe = (self.receive_pipe + receive_pipe) / 2;
		}
	}
}
