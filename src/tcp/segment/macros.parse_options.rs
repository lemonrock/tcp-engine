// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


macro_rules! parse_option_variable_length_including_option_kind_and_length_fields
{
	($packet: ident, $pointer_to_option_kind: ident, $end_pointer: ident) =>
	{
		{
			let pointer_to_length = $pointer_to_option_kind + 1;
		
			if unlikely(pointer_to_length == $end_pointer)
			{
				drop!($packet, "TCP option (other than 0 and 1) had missing length")
			}
		
			let length_including_option_kind_and_length_fields = TcpOptions::parse_option_length_without_checks(pointer_to_length);
			if unlikely(length_including_option_kind_and_length_fields < 2)
			{
				drop!($packet, "TCP option length (variable) is too small")
			}
			
			if unlikely($pointer_to_option_kind + (length_including_option_kind_and_length_fields as usize) > $end_pointer)
			{
				drop!($packet, "TCP option length (variable) overflows options space in TCP header")
			}
			
			length_including_option_kind_and_length_fields
		}
	}
}

macro_rules! parse_option_known_length
{
	($packet: ident, $pointer_to_option_kind: ident, $end_pointer: ident, $known_length: ident) =>
	{
		{
			if unlikely($pointer_to_option_kind + $known_length > $end_pointer)
			{
				drop!($packet, "TCP option length (known) overflows options space in TCP header")
			}
		
			if cfg!(target_feature = "drop-options-known-fixed-length-invalid")
			{
				let pointer_to_length = $pointer_to_option_kind + 1;
				let length = TcpOptions::parse_option_length_without_checks(pointer_to_length);
				
				if unlikely(length != $known_length as u8)
				{
					drop!($packet, "TCP option known length did not match length in packet")
				}
			}
			
			$pointer_to_option_kind + TcpOptions::LengthOverhead
		}
	}
}

macro_rules! parse_unsupported_or_unknown_option
{
	($packet: ident, $pointer_to_option_kind: ident, $end_pointer: ident, $duplicate_unknown_options: ident, $option_kind: expr) =>
	{
		{
			if unlikely($duplicate_unknown_options.contains($option_kind))
			{
				drop!($packet, "TCP option was a duplicate of an unknown option")
			}
			$duplicate_unknown_options.insert($option_kind);
			
			parse_option_variable_length_including_option_kind_and_length_fields!($packet, $pointer_to_option_kind, $end_pointer) as usize
		}
	}
}

macro_rules! parse_selective_acknowledgment_block
{
	($packet: ident, $pointer_to_block: ident) =>
	{
		{
			let block: (NetworkEndianU32, NetworkEndianU32) = unsafe { * ($pointer_to_block as *const (NetworkEndianU32, NetworkEndianU32)) };
			let block = (WrappingSequenceNumber(block.0.to_native_endian()), WrappingSequenceNumber(block.1.to_native_endian()));
			let left_edge_of_block = block.0;
			let right_edge_of_block = block.1;
			let right_edge_of_block_is_not_greater_than_left_edge = !(block.0 < block.1);
			if unlikely(right_edge_of_block_is_not_greater_than_left_edge)
			{
				drop!($packet, "TCP selective acknowledgment option had a block whose right edge was not greater than the left edge")
			}
			SelectiveAcknowledgmentBlock
			{
				left_edge_of_block,
				right_edge_of_block,
			}
		}
	}
}

macro_rules! parse_options
{
	($packet: ident, $minimum_tcp_maximum_segment_size_option: ident, $options_data_pointer: ident, $options_data_length: ident, $all_flags: ident) =>
	{
		{
			let mut tcp_options = TcpOptions::default();
			let mut duplicate_unknown_options = TcpOptionsBitSet::new();
		
			let mut pointer_to_option_kind = $options_data_pointer;
			let end_pointer = pointer_to_option_kind + $options_data_length;
			
			while pointer_to_option_kind != end_pointer
			{
				let length = match TcpOptions::parse_option_kind_without_checks(pointer_to_option_kind)
				{
					// End Of Options List
					//
					// "This option code may be used between options, for example, to align the beginning of a subsequent option on a word boundary.
					// There is no guarantee that senders will use this option, so receivers must be prepared to process options even if they do not begin on a word boundary."
					//
					// IANA (https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml): "Options 0 and 1 are exactly one octet which is their kind field."
					//
					// Defined in RFC 793.
					0 =>
					{
						if cfg!(target_feature = "drop-options-padding-non-zero")
						{
							let mut pointer_to_padding = pointer_to_option_kind + 1;
							
							// Check remaining space is all zeros.
							// Note that this check could be made more efficient by looping 8 bytes at a time.
							while pointer_to_padding != end_pointer
							{
								if unlikely(unsafe { *(pointer_to_padding as *const u8) } != 0x00)
								{
									drop!($packet, "Padding at end of options list was not zero")
								}
							
								pointer_to_padding += 1;
							}
						}
						break
					},
					
					// No Operation (No-Op)
					//
					// "This option code indicates the end of the option list.
					// This might not coincide with the end of the TCP header according to the Data Offset field.
					// This is used at the end of all options, not the end of each option, and need only be used if the end of the options would not otherwise coincide with the end of the TCP header."
					//
					// IANA (https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml): "Options 0 and 1 are exactly one octet which is their kind field."
					//
					// Defined in RFC 793.
					1 => 1,
					
					// Maximum Segment Size
					//
					// "If this option is present, then it communicates the maximum receive segment size at the TCP which sends this segment.
					// This field must only be sent in the initial connection request (in packets with the SYN control bit set).
					// If this option is not used, any segment size is allowed."
					//
					// RFC 1122 however defines a missing Maximum Segment Size option as inferring 536 bytes.
					//
					// Defined in RFC 793.
					MaximumSegmentSizeOption::Kind =>
					{
						const KnownLength: usize = MaximumSegmentSizeOption::KnownLength;
						
						if unlikely(tcp_options.has_maximum_segment_size())
						{
							drop!($packet, "TCP option maximum segment size was duplicated")
						}
						
						if unlikely(!$all_flags.contains(Flags::Synchronize))
						{
							drop!($packet, "TCP option maximum segment size was specified on a segment without a Synchronize flag")
						}
						
						let pointer_to_data = parse_option_known_length!($packet, pointer_to_option_kind, end_pointer, KnownLength);
						
						let maximum_segment_size = MaximumSegmentSizeOption(unsafe { *(pointer_to_data as *const NetworkEndianU16) });
						if unlikely(maximum_segment_size < $minimum_tcp_maximum_segment_size_option)
						{
							drop!($packet, "TCP option maximum segment size was smaller than minimum_tcp_maximum_segment_size_option")
						}
						
						tcp_options.maximum_segment_size = Some(maximum_segment_size);
						
						KnownLength
					}
					
					// Window Scale
					//
					// Definition updated in RFC 7323.
					WindowScaleOption::Kind =>
					{
						const KnownLength: usize = WindowScaleOption::KnownLength;
						
						if unlikely(tcp_options.has_window_scale())
						{
							drop!($packet, "TCP option window scale was duplicated")
						}
						
						let pointer_to_data = parse_option_known_length!($packet, pointer_to_option_kind, end_pointer, KnownLength);
						tcp_options.window_scale =
						{
							const Rfc7323MaximumInclusiveWindowScale: u8 = 14;
							let raw_window_scale = unsafe { *(pointer_to_data as *const u8) };
							if unlikely(raw_window_scale > Rfc7323MaximumInclusiveWindowScale)
							{
								drop!($packet, "TCP option window scale exceeded the RFC 7323 maximum of 14")
							}
							Some(WindowScaleOption(raw_window_scale))
						};
						
						KnownLength
					}
					
					// Selective Acknowledgment Permitted (`SACK_PERM`)
					//
					// Definition in RFC 2018.
					SelectiveAcknowledgmentOption::SelectiveAcknowledgmentPermittedOptionKind =>
					{
						const KnownLength: usize = SelectiveAcknowledgmentOption::SelectiveAcknowledgmentPermittedOptionKnownLength;
						
						if unlikely(tcp_options.has_selective_acknowledgment_permitted())
						{
							drop!($packet, "TCP option selective acknowledgment permitted was duplicated")
						}
						
						if unlikely(!$all_flags.contains(Flags::Synchronize))
						{
							drop!($packet, "TCP option selective acknowledgment permitted was specified on a segment other than Synchronize")
						}
						
						parse_option_known_length!($packet, pointer_to_option_kind, end_pointer, KnownLength);
						tcp_options.selective_acknowledgment_permitted = true;
						
						KnownLength
					}
					
					// Selective Acknowledgment
					//
					// Definition in RFC 2018.
					SelectiveAcknowledgmentOption::Kind =>
					{
						if unlikely(tcp_options.has_selective_acknowledgment())
						{
							drop!($packet, "TCP option selective acknowledgment was duplicated")
						}
						
						if unlikely(!$all_flags.contains(Flags::Acknowledgment))
						{
							drop!($packet, "TCP option selective acknowledgment permitted was specified on a segment other than Acknowledgment")
						}

						let length = parse_option_variable_length_including_option_kind_and_length_fields!($packet, pointer_to_option_kind, end_pointer) as usize;
						
						const BlockLength: usize = 8;
						
						const OneBlockLength: usize = 2 + BlockLength;
						
						const TwoBlocksLength: usize = OneBlockLength + BlockLength;
						
						const ThreeBlocksLength: usize = TwoBlocksLength + BlockLength;
						
						const FourBlocksLength: usize = ThreeBlocksLength + BlockLength;
						
						let pointer_to_first_block = pointer_to_option_kind + TcpOptions::LengthOverhead;
						
						tcp_options.selective_acknowledgment = match length
						{
							SelectiveAcknowledgmentOption::OneBlockLength =>
							{
								let first_block = parse_selective_acknowledgment_block!($packet, pointer_to_first_block);
								Some(SelectiveAcknowledgmentOption::one_block(first_block))
							},
							
							SelectiveAcknowledgmentOption::TwoBlocksLength =>
							{
								let first_block = parse_selective_acknowledgment_block!($packet, pointer_to_first_block);
								let pointer_to_second_block = pointer_to_first_block + SelectiveAcknowledgmentOption::BlockLength;
								let second_block = parse_selective_acknowledgment_block!($packet, pointer_to_second_block);
								Some(SelectiveAcknowledgmentOption::two_blocks(first_block, second_block))
							}
							
							SelectiveAcknowledgmentOption::ThreeBlocksLength =>
							{
								let first_block = parse_selective_acknowledgment_block!($packet, pointer_to_first_block);
								let pointer_to_second_block = pointer_to_first_block + SelectiveAcknowledgmentOption::BlockLength;
								let second_block = parse_selective_acknowledgment_block!($packet, pointer_to_second_block);
								let pointer_to_third_block = pointer_to_second_block + SelectiveAcknowledgmentOption::BlockLength;
								let third_block = parse_selective_acknowledgment_block!($packet, pointer_to_third_block);
								Some(SelectiveAcknowledgmentOption::three_blocks(first_block, second_block, third_block))
							}
							
							SelectiveAcknowledgmentOption::FourBlocksLength =>
							{
								let first_block = parse_selective_acknowledgment_block!($packet, pointer_to_first_block);
								let pointer_to_second_block = pointer_to_first_block + SelectiveAcknowledgmentOption::BlockLength;
								let second_block = parse_selective_acknowledgment_block!($packet, pointer_to_second_block);
								let pointer_to_third_block = pointer_to_second_block + SelectiveAcknowledgmentOption::BlockLength;
								let third_block = parse_selective_acknowledgment_block!($packet, pointer_to_third_block);
								let pointer_to_fourth_block = pointer_to_second_block + SelectiveAcknowledgmentOption::BlockLength;
								let fourth_block = parse_selective_acknowledgment_block!($packet, pointer_to_fourth_block);
								Some(SelectiveAcknowledgmentOption::four_blocks(first_block, second_block, third_block, fourth_block))
							}
							
							_ => drop!($packet, "TCP option selective acknowledgment had more than 4 blocks (this error should not occur if option length is being properly validated)"),
						};
						
						length
					}
					
					// Timestamps
					//
					// Definition updated in RFC 7323.
					//
					// "The Timestamps option may appear in any data or <ACK> segment, adding 10 bytes (up to 12 bytes including padding) to the 20-byte TCP header.
					// It is required that this TCP option will be sent on all non-<SYN> packets after an exchange of options on the <SYN> packets has indicated that both sides understand this extension."
					//
					// "Once TSopt has been successfully negotiated, that is both <SYN> and <SYN,ACK> contain TSopt, the TSopt MUST be sent in every non-<RST> segment for the duration of the connection, and SHOULD be sent in an <RST> segment."
					//
					// "The TSecr field is valid if the ACK bit is set in the TCP header.
					// If the ACK bit is not set in the outgoing TCP header, the sender of that segment SHOULD set the TSecr field to zero."
					//
					// Not supported by Windows since Windows 7.
					TimestampsOption::Kind =>
					{
						const KnownLength: usize = TimestampsOption::KnownLength;
						
						if unlikely(tcp_options.has_timestamps())
						{
							drop!($packet, "TCP option timestamps was duplicated")
						}
						
						let pointer_to_data = parse_option_known_length!($packet, pointer_to_option_kind, end_pointer, KnownLength);
						tcp_options.timestamps = if $all_flags.contains(Flags::Acknowledgment)
						{
							Some(unsafe { *(pointer_to_data as *const TimestampsOption) })
						}
						else
						{
							Some(TimestampsOption::from_TSval_only(unsafe { *(pointer_to_data as *const NetworkEndianU32) }))
						};
						
						KnownLength
					}
					
					// MD5 Signature Option (obsolete)
					//
					// Definition in RFC 2385 and obsoleted by RFC 5925 (TCP Authentication Option).
					//
					// However, it is still used and it conflicts with the TCP Authentication Option.
					AuthenticationOption::Md5SignatureOptionKind =>
					{
						const KnownLength: usize = AuthenticationOption::Md5SignatureOptionKnownLength;
						
						if unlikely(tcp_options.has_authentication())
						{
							drop!($packet, "TCP option MD5 was duplicated or specified in addition to TCP option authentication")
						}
						
						tcp_options.authentication =
						{
							let pointer_to_data = parse_option_known_length!($packet, pointer_to_option_kind, end_pointer, KnownLength);
							let digest = unsafe { NonNull::new_unchecked(pointer_to_data as *mut [u8; 16]) };
							
							Some(AuthenticationOption(Authentication::Rfc2385ObsoleteMD5 { digest }))
						};
						
						KnownLength
					}
					
					// Quick-Start Response
					//
					// Definition in RFC 4782.
					//
					// "When used for initial start-up, the Quick-Start Request packet can be either the SYN or SYN/ACK packet".
					// "The TCP receiver (say, host B) returns the Quick-Start Response option in the TCP header in the responding SYN/ACK packet or ACK packet, called the Quick-Start Response packet, informing host A of the results of their request".
					//
					// Not widely used, if at all.
					27 =>
					{
						// Since we:-
						//
						// * do not issue Quick-Start Requests by adding IPv4 / IPv6 options to outgoing packets;
						// * do not respond to Quick-Start Requests
						//
						// any such Quick-Start Response option in a packet is malformed, and so we should just drop the packet.
						
						drop!($packet, "TCP option Quick-Start Response should never be received as we never initiate Quick-Start or respond passively to Quick-Start Request")
					}
					
					// User Timeout, also known as `UTO`.
					//
					// Definition in RFC 5482.
					//
					// IANA (https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml): "This value has been deployed on the Internet in ways that are not compatible with the documented use in this IANA allocation". F5 () report "In Akamai’s IPA and SXL product lines, they support client IP visibility by embedding a version number (one byte) and an IPv4 address (four bytes) as part of their overlay path feature in tcp option number 28."
					//
					// "A TCP User Timeout Option with a "User Timeout" field of zero and a "Granularity" bit of either minutes (1) or seconds (0) is reserved for future use. Current TCP implementations MUST NOT send it and MUST ignore it upon reception."
					//
					// Not widely used, if at all - and not helped by the conflicting uses of this option, one of which is by a big Internet company.
					UserTimeOutOption::Kind =>
					{
						let length = parse_option_variable_length_including_option_kind_and_length_fields!($packet, pointer_to_option_kind, end_pointer) as usize;
						
						const KnownOfficialRfc5482Length: usize = UserTimeOutOption::KnownLength;
						
						const KnownUnofficialAkamaiLength: usize = 5;
						
						match length
						{
							KnownOfficialRfc5482Length =>
							{
								if unlikely(tcp_options.has_user_time_out())
								{
									drop!($packet, "TCP option User Time Out was duplicated")
								}
								
								tcp_options.user_time_out =
								{
									let pointer_to_data = pointer_to_option_kind + TcpOptions::LengthOverhead;
									let raw_user_timeout = unsafe { *(pointer_to_data as *const NetworkEndianU32) };
									
									if raw_user_timeout == NetworkEndianU32::Zero || raw_user_timeout == NetworkEndianU32::TopBitSetOnly
									{
										drop!($packet, "TCP option User Time Out had an invalid all-zero time out")
									}
									
									Some(UserTimeOutOption(raw_user_timeout))
								};
							},
							
							KnownUnofficialAkamaiLength =>
							{
								if duplicate_unknown_options.contains(28)
								{
									drop!($packet, "TCP option 28 (Akamai unofficial squatting) was duplicated")
								}
								
								duplicate_unknown_options.insert(28);
								
							},
							
							_ => drop!($packet, "TCP option 28 was neither user time out nor Akamai unofficial squatting")
						}
					
						length
					}
					
					// Authentication
					//
					// Also known as `TCP-AO` and `TCP Authentication Option`.
					//
					// Replacement for the obsolete `MD5 Signature Option` defined in RFC 2385.
					//
					// "An endpoint MUST NOT use TCP-AO for the same connection in which TCP MD5 is used.
					// When both options appear, TCP MUST silently discard the segment."
					//
					// Definition in RFC 5925.
					//
					// Not widely used, if at all.
					AuthenticationOption::Kind =>
					{
						if unlikely(tcp_options.has_authentication())
						{
							drop!($packet, "TCP option authentication was duplicated or specified in addition to TCP option MD5")
						}
						
						let length = parse_option_variable_length_including_option_kind_and_length_fields!($packet, pointer_to_option_kind, end_pointer);
						
						const MinimumLength: u8 = 4;
						
						if unlikely(length < MinimumLength)
						{
							drop!($packet, "TCP option authentication was less than the minimum length of 4")
						}
						
						tcp_options.authentication =
						{
							let pointer_to_data = pointer_to_option_kind + TcpOptions::LengthOverhead;
							
							let key_id = unsafe { *(pointer_to_data as *const u8) };
							let r_next_key_id = unsafe { *((pointer_to_data + 1) as *const u8) };
							let message_authentication_code_length = length - MinimumLength;
							let message_authentication_code = unsafe { NonNull::new_unchecked((pointer_to_data + 2) as *mut u8) };
							
							Some(AuthenticationOption(Authentication::Rfc5926Authentication { key_id, r_next_key_id, message_authentication_code_length, message_authentication_code }))
						};
						
						length as usize
					}
					
					// Multipath TCP
					//
					// Also known as `MPTCP`.
					//
					// Definition in RFC 6824.
					//
					// Only Apple Darwin (Mac OS X, iOS) systems use this widely as of 2018.
					//
					// The Length can be either 12 or 20. It is likely if Multipath TCP becomes widespread that protocol attacks will be developed which will try to exploit the complexity of the option structure.
					30 => parse_unsupported_or_unknown_option!($packet, pointer_to_option_kind, end_pointer, duplicate_unknown_options, 30),
					
					// TCP Fast Open Cookie
					//
					// Definition in RFC 7413.
					//
					// Permits data carried in the Synchronize and SynchronizeAcknowledgment handshake to be passed to the application immediately, rather than on completion of the three-way handshake.
					34 => parse_unsupported_or_unknown_option!($packet, pointer_to_option_kind, end_pointer, duplicate_unknown_options, 34),
					
					// Unsupported: Draft TCP Jumbo Options: https://www.imperialviolet.org/binary/jumbo-tcp-options.html
					// 42 or 43
					
					// RFC 1122 Section 4.2.2.5: "A TCP MUST ignore without error any TCP option it does not implement, assuming that the option has a length field (all TCP options defined in the future will have length fields)."
					option_kind @ _ => parse_unsupported_or_unknown_option!($packet, pointer_to_option_kind, end_pointer, duplicate_unknown_options, option_kind),
				};
				
				pointer_to_option_kind += length;
			}
			
			tcp_options
		}
	}
}
