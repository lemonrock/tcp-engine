// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Based on an original idea by Daniel J Bernstein.
///
/// Logic here in is inspired by:-
///
/// * Appendix A, RFC 4987, which details two different approaches by Daniel J Bernstein;
/// * Linux source code as of June 13, 2018
/// * FreeBSD source code as of June 13, 2018
/// * OpenBSD source code as of June 13, 2018
///
/// A syncookie is a 32-bit value used for the initial sequence number (ISN) in a listening server's SynchronizeAcknowledgment reply segment.
///
/// It encodes two important properties:-
///
/// * A value which, when acknowledged by the recepient, identifies this as a genuine connection attempt
/// * A set of values, in a compressed form, of some of the most important TCP options
///
/// Our syncookies closely match those in FreeBSD and OpenBSD:-
///
/// ```
/// Bit Index:    0  1  2  3  4  5  6  7  8  9  10  11  12  13  14  15  16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31
/// Bit Meaning:  x  x  x  x  x  x  x  x  x  x   x   x   x   x   x   x   x   x   x   x   x   x   x   W   W   W   m   m   m   S   E   p
/// ```
///
/// Where:-
///
/// * `x` is a 23-bit, truncated message authentication code (MAC) (XOR of 2 32-bit values, then truncated to 32-bits).
/// * `W` is a 3-bit unsigned index into a known table of window scale values.
/// * `m` is a 3-bit unsigned index into a known table of maximum segment size values.
/// * `S` is a 1-bit boolean value, which, if set, indicates selective acknowledgment (SACK) is permitted.
/// * `E` is a 1-bit boolean value, which, if set, indicates support for explicit congestion notification (ECN) is permitted.
/// * `P` is a 1-bit unsigned index indicating which of two secret keys are used
///
/// To prevent replay attacks two secret keys are maintained for the message authentication code (MAC), a current one and a retired one.
///
/// * The current one is used to generate message authentication codes for new syncookies. It is retired after 15 seconds.
/// * The retired one is kept for 15 seconds to authenticate previously generated syncookies. After 15 seconds it is regenerated, and swaps places with the current one.
///
/// A key can live for a maximum of 30 seconds and so a syncookie is only valid for a maximum of 30 seconds. This retirement logic is in `SipHashKey`.
///
/// There are three potential attacks:-
///
/// * Attacking the secret, by either:-
///   * Finding a weakness in the message authentication code (MAC) function (SIP-HASH-2-4);
///   * Finding a weakness in the way the message authentication code (MAC) function is used;
///
/// * A collision attack on the message authentication code (MAC) of a single acknowledgment.
///
/// * Finding a way to make the message authentication code (MAC) function consume most of the CPU's available cycles.
///
/// The first attack must be completed in less than thirty seconds.
///
/// The second attack requires an average of 2,411 attempts for a 50% chance of success (the Birthday paradox), and a way for the attacker to infer success of his spoofed packets using a side-channel. For a sustained rate of 100 spoofed connections per second approximately 900,000 packets per second would have to be sent.
///
/// The third is not known to be possible with SIP-HASH-2-4, the current message authentication code (MAC) function.
#[derive(Default, Debug)]
pub struct SynCookieProtection
{
	secret_keys: [SipHashKey; 2],
	current_secret_key_index: Cell<u64>,
	last_key_rotation_at: Cell<MonotonicMillisecondTimestamp>,
}

impl SynCookieProtection
{
	const RotateKeysAfterThisManyMilliseconds: MillisecondDuration = MillisecondDuration::FifteenSeconds;
	
	const TotalBits: u32 = 32;
	
	const MessageAuthenticationCodeBits: u32 = 23;
	
	const TcpOptionsMask: u32 = (1 << (Self::TotalBits - Self::MessageAuthenticationCodeBits)) - 1;
	
	const MessageAuthenticationCodeMask: u32 = !Self::TcpOptionsMask;
	
	const TcpOptionsStartAtBit: u32 = Self::TotalBits - Self::MessageAuthenticationCodeBits;
	
	const MaximumSegmentSizeBits: u32 = 3;
	const MaximumSegmentSizeIndexBitShift: u8 = (Self::TcpOptionsStartAtBit - Self::MaximumSegmentSizeBits) as u8;
	const MaximumSegmentSizeIndexBitMask: u32 = ((1 << Self::MaximumSegmentSizeBits) - 1) << (Self::MaximumSegmentSizeIndexBitShift as u32);
	
	const WindowScaleIndexBits: u32 = 3;
	const WindowScaleIndexBitShift: u8 = (Self::TcpOptionsStartAtBit - Self::MaximumSegmentSizeBits - Self::WindowScaleIndexBits) as u8;
	const WindowScaleIndexIndexBitMask: u32 = ((1 << Self::WindowScaleIndexBits) - 1) << (Self::WindowScaleIndexBitShift as u32);
	
	const SelectiveAcknowledgmentPermittedBits: u32 = 1;
	const SelectiveAcknowledgmentPermittedBit: u8 = (Self::SelectiveAcknowledgmentPermittedBits << (Self::TcpOptionsStartAtBit - Self::MaximumSegmentSizeBits - Self::WindowScaleIndexBits - Self::SelectiveAcknowledgmentPermittedBits)) as u8;
	
	const ExplicitCongestionNotificationPermittedBits: u32 = 1;
	const ExplicitCongestionNotificationPermittedBit: u8 = (Self::ExplicitCongestionNotificationPermittedBits << (Self::TcpOptionsStartAtBit - Self::MaximumSegmentSizeBits - Self::WindowScaleIndexBits - Self::SelectiveAcknowledgmentPermittedBits - Self::ExplicitCongestionNotificationPermittedBits)) as u8;
	
	const SecretKeyIndexBits: u32 = 1;
	const SecretKeyIndexBit: u8 = (Self::SecretKeyIndexBits << 0) as u8;
	
	/// Creates a new instance.
	#[inline(always)]
	pub fn new(now: MonotonicMillisecondTimestamp) -> Self
	{
		Self
		{
			secret_keys: [SipHashKey::default(), SipHashKey::default()],
			current_secret_key_index: Cell::new(0),
			last_key_rotation_at: Cell::new(now),
		}
	}
	
	/// Creates an initial sequence number suitable for a SynchronizeAcknowledgment.
	#[allow(non_snake_case)]
	#[inline(always)]
	pub fn create_syn_cookie_for_synchronize_acnowledgment<Address: InternetProtocolAddress>(&self, now: MonotonicMillisecondTimestamp, source_internet_protocol_address: &Address, destination_internet_protocol_address: &Address, SEG_SEQ: WrappingSequenceNumber, source_port_destination_port: SourcePortDestinationPort, SEG_maximum_segment_size: Option<MaximumSegmentSizeOption>, SEQ_window_scale: Option<WindowScaleOption>, selective_acknowledgment_permitted: bool, explicit_congestion_notification_supported: bool) -> WrappingSequenceNumber
	{
		self.rotate_secret_keys_if_required(now);
		
		let (tcp_options, current_secret_key_index) = self.tcp_options::<Address>(SEG_maximum_segment_size, SEQ_window_scale, selective_acknowledgment_permitted, explicit_congestion_notification_supported);
		
		let IRS = SEG_SEQ;
		
		let message_authentication_code = self.message_authentication_code(current_secret_key_index, source_internet_protocol_address, destination_internet_protocol_address, source_port_destination_port, IRS, tcp_options);
		
		// Add the `tcp_options` by XOR against the `message_authentication_code` which:-
		//
		// * Allows us to pass them back to ourselves;
		// * Increases initial sequence number variance;
		// * Makes sure the `tcp_options` are not clearly visible on the wire.
		//
		// This does not enhance cryptographic strength.
		let message_authentication_code_top_23_bits = message_authentication_code & Self::MessageAuthenticationCodeMask;
		let tcp_options_xored_against_message_authentication_code = (tcp_options as u32) ^ (message_authentication_code >> Self::MessageAuthenticationCodeBits);
		
		WrappingSequenceNumber::from(message_authentication_code_top_23_bits | tcp_options_xored_against_message_authentication_code)
	}
	
	/// Validate as syn cookie returned in the final ACK of the initial TCP three-way handshake.
	#[allow(non_snake_case)]
	#[inline(always)]
	pub fn validate_syncookie_in_acknowledgment<Address: InternetProtocolAddress>(&self, source_internet_protocol_address: &Address, destination_internet_protocol_address: &Address, SEG_ACK: WrappingSequenceNumber, SEG_SEQ: WrappingSequenceNumber, source_port_destination_port: SourcePortDestinationPort) -> Result<ParsedSynCookie, ()>
	{
		let ISS = SEG_ACK - 1;
		let IRS = SEG_SEQ - 1;
		
		let syncookie: u32 = ISS.into();
		
		let tcp_options = ((syncookie & Self::TcpOptionsMask) ^ (syncookie >> Self::MessageAuthenticationCodeBits)) as u8;
		
		let secret_key_index = (tcp_options & Self::SecretKeyIndexBit) as u64;
		
		let message_authentication_code = self.message_authentication_code(secret_key_index, source_internet_protocol_address, destination_internet_protocol_address, source_port_destination_port, IRS, tcp_options);
		
		let recomputed_message_authentication_code_matches_that_from_sender = (syncookie & Self::MessageAuthenticationCodeMask) == (message_authentication_code & Self::MessageAuthenticationCodeMask);
		
		if likely!(recomputed_message_authentication_code_matches_that_from_sender)
		{
			Ok
			(
				ParsedSynCookie
				{
					IRS,
					ISS,
					their_maximum_segment_size: SortedCommonMaximumSegmentSizes::new::<Address>().decode_maximum_segment_size_from_index(tcp_options & (Self::MaximumSegmentSizeIndexBitMask as u8) >> Self::MaximumSegmentSizeIndexBitShift),
					their_window_scale: SortedCommonWindowScales::new::<Address>().decode_window_scale_from_index(tcp_options & (Self::WindowScaleIndexIndexBitMask as u8) >> Self::WindowScaleIndexBitShift),
					their_selective_acknowledgment_permitted: tcp_options & Self::SelectiveAcknowledgmentPermittedBit != 0,
					explicit_congestion_notification_supported: tcp_options & Self::ExplicitCongestionNotificationPermittedBit != 0,
				}
			)
		}
		else
		{
			Err(())
		}
	}
	
	#[inline(always)]
	fn current_secret_key_index(&self) -> u64
	{
		self.current_secret_key_index.get() & 0x1
	}
	
	#[inline(always)]
	fn current_secret_key(&self) -> &SipHashKey
	{
		self.secret_key_for_index(self.current_secret_key_index())
	}
	
	#[inline(always)]
	fn secret_key_for_index(&self, index: u64) -> &SipHashKey
	{
		unsafe { self.secret_keys.get_unchecked(index as usize) }
	}
	
	#[inline(always)]
	fn rotate_secret_keys_if_required(&self, now: MonotonicMillisecondTimestamp)
	{
		let last_key_rotation_at = self.last_key_rotation_at.get();
		debug_assert!(last_key_rotation_at <= now, "last_key_rotation_at '{:?}' is greater than now '{:?}'", last_key_rotation_at, now);
		
		let should_rotate_keys = last_key_rotation_at - now >= Self::RotateKeysAfterThisManyMilliseconds;
		if unlikely!(should_rotate_keys)
		{
			self.current_secret_key_index.set(self.current_secret_key_index.get() + 1);
			self.current_secret_key().regenerate();
			self.last_key_rotation_at.set(now);
		}
	}
	
	/// IRS is the Initial Receiver Sequence number.
	///
	/// RFC 793, Glossary, Page 80: "The Initial Receive Sequence number.
	/// The first sequence number used by the sender on a connection".
	#[allow(non_snake_case)]
	#[inline(always)]
	fn message_authentication_code<Address: InternetProtocolAddress>(&self, secret_key_index: u64, source_internet_protocol_address: &Address, destination_internet_protocol_address: &Address, source_port_destination_port: SourcePortDestinationPort, IRS: WrappingSequenceNumber, tcp_options: u8) -> u32
	{
		let mut sip_hasher = self.secret_key_for_index(secret_key_index).new_hasher();
		source_internet_protocol_address.write_to_hash(&mut sip_hasher);
		destination_internet_protocol_address.write_to_hash(&mut sip_hasher);
		sip_hasher.write_u32(source_port_destination_port.to_big_endian_u32());
		sip_hasher.write_u32(IRS.into());
		sip_hasher.write_u8(tcp_options);
		let sip_hash = sip_hasher.finish();
		
		let hashes: [u32; 2] = unsafe { transmute(sip_hash) };
		let message_authentication_code = unsafe { *hashes.get_unchecked(0) ^ *hashes.get_unchecked(1) };
		
		message_authentication_code
	}
	
	#[inline(always)]
	fn tcp_options<Address: InternetProtocolAddress>(&self, maximum_segment_size: Option<MaximumSegmentSizeOption>, window_scale: Option<WindowScaleOption>, selective_acknowledgment_permitted: bool, explicit_congestion_notification_supported: bool) -> (u8, u64)
	{
		let mut tcp_options;
		
		let maximum_segment_size_index = SortedCommonMaximumSegmentSizes::new::<Address>().encode_maximum_segment_size_as_index(maximum_segment_size.unwrap_or_default());
		tcp_options = maximum_segment_size_index << Self::MaximumSegmentSizeIndexBitShift;
		
		let window_scale_index = SortedCommonWindowScales::new::<Address>().encode_window_scale_as_index(window_scale);
		tcp_options |= window_scale_index << Self::WindowScaleIndexBitShift;
		
		if selective_acknowledgment_permitted
		{
			tcp_options |= Self::SelectiveAcknowledgmentPermittedBit;
		}
		
		if explicit_congestion_notification_supported
		{
			tcp_options |= Self::ExplicitCongestionNotificationPermittedBit;
		}
		
		let current_secret_key_index = self.current_secret_key_index();
		
		tcp_options |= current_secret_key_index as u8;
		
		(tcp_options, current_secret_key_index)
	}
}
