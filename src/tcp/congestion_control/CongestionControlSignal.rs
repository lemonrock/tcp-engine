// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) enum CongestionControlSignal
{
	CC_NDUPACK,
	CC_ECN,
	CC_RTO,
	CC_RTO_ERR,
}



impl CongestionControlSignal
{
	#[inline(always)]
	fn signal<TCBA: TransmissionControlBlockAbstractions>(self, transmission_control_block: &mut TransmissionControlBlock<TCBA>, SEG: &TcpSegment)
	{
		use self::CongestionControlSignal::*;
		
		match self
		{
			CC_NDUPACK =>
			{
				if !transmission_control_block.congestion_control.congestion_recovery.IN_FASTRECOVERY()
				{
					transmission_control_block.congestion_control.snd_recover = transmission_control_block.SND.NXT;
					
					transmission_control_block.explicit_congestion_notification_reduced_congestion_window();
				}
			}
			
			CC_ECN =>
			{
				if !transmission_control_block.congestion_control.congestion_recovery.IN_CONGRECOVERY()
				{
					TCPSTAT_INC(tcps_ecn_rcwnd);
					
					transmission_control_block.congestion_control.snd_recover = transmission_control_block.SND.NXT;
				}
			}
			
			CC_RTO =>
			{
				let maxseg = transmission_control_block.congestion_control.recalculate_sender_maximum_segment_size();
				transmission_control_block.congestion_control.number_of_duplicate_acknowledgments_received_since_SND_UNA_advanced = 0;
				transmission_control_block.congestion_control.bytes_acked = 0;
				transmission_control_block.congestion_control.congestion_recovery.exit_recovery();
				transmission_control_block.congestion_control.snd_ssthresh = max(2, min(transmission_control_block.SND.WND, transmission_control_block.congestion_control.cwnd) / 2 / maxseg) * maxseg;
				transmission_control_block.congestion_control.cwnd = maxseg;
			}
			
			CC_RTO_ERR =>
			{
				TCPSTAT_INC(tcps_sndrexmitbad);
				
				// TODO: FreeBSD: "RTO was unnecessary, so reset everything".
				transmission_control_block.congestion_control.cwnd = transmission_control_block.congestion_control.cwnd_prev;
				transmission_control_block.congestion_control.snd_ssthresh = transmission_control_block.congestion_control.snd_ssthresh_prev;
				transmission_control_block.congestion_control.snd_recover = transmission_control_block.congestion_control.snd_recover_prev;
				
				if transmission_control_block.congestion_control.TF_WASFRECOVERY
				{
					transmission_control_block.congestion_control.congestion_recovery.enter_fast_recovery();
				}
	
				if transmission_control_block.congestion_control.TF_WASCRECOVERY
				{
					transmission_control_block.congestion_control.congestion_recovery.enter_congestion_recovery();
				}
				
				// TODO: TF_PREVVALID. - prevous is valid - is that something to do with cwnd_prev et al?
				// Seems so. We could use a Rust Option instead.
				// prev values are related to the following FreeBSD code comments:
				// - "bad retransmit" recovery without timestamps? See
				// - If we just performed our first retransmit, and the ACK arrives within our recovery window, then it was a mistake to do the retransmit in the first place.  Recover our original cwnd and ssthresh, and proceed to transmit where we left off.
				// - first retransmit [in RTO timer]; record ssthresh and cwnd so they can be recovered if this turns out to be a "bad" retransmit. A retransmit is considered "bad" if an ACK for this segment is received within RTT/2 interval; the assumption here is that the ACK was already in flight.  See "On Estimating End-to-End Network Path Properties" by Allman and Paxson for more details.
				//
				// The Allman paper is from 1999. We might want to use F-RTO, RFC 5682, instead. (F-RTO: The basic idea is to send
				//      previously unsent data after the first retransmission after a RTO.
				//      If the ACKs advance the window, the RTO may be declared spurious).
				
				// TODO: RFC 5681 (core congestion control) and RFC 6582 (NewReno).
				// TODO READ: RFC 3390
				// TODO: RFC 3465 - byte counting for congestion control - closes a security hole.
				// TODO: RFC 3042
				// TODO: RFC 6675 (Using SACK for loss recovery) (affects lots of stuff).
				
				transmission_control_block.t_flags &= !TF_PREVVALID;
				transmission_control_block.t_badrxtwin = 0;
			}
		}
		
		transmission_control_block.congestion_control.curack = SEG.ACK();
		transmission_control_block.congestion_control_implementation.signal(self);
	}
}
