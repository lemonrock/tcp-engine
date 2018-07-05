# tcp-engine

[tcp-engine] is a rust crate.


## Licensing

The license for this project is AGPL3.


## Security and Robustness Features Supported

* Fixed size memory usage for transmission control blocks and related structures at start-up; no dynamic memory allocation per connection;
* Urgent segments are not permitted;
* Non-zero padding and urgent pointers are disallowed;
* TCP known options are always length checked;
* Push flag is always ignored;
* Invalid flag combinations are blackholed;
* Unusual but valid combinations are blackholed;
* Fixed memory usage at start-up;
* Alarm wheels of fixed size with fixed sized 'ticks' to prevent unbounded and unstable alarm growth (memory for alarms is statically allocated at start up);
* SYN flooding defences are permanently on: there is no syncache;
* MSS clamping
    * Connections with a small MSS are refused (usually under 984 on IPv4 and 1220 on IPv6);
    * Connections without a MSS option default to the Path MSS, rather than the TCP minimum;
* ICMP and ICMPv6 messages are completely ignored to make attackers time harder:-
    * There is no Path MTU discovery;
    * Connection failures ignored;
* Invalid packets are blackholed rather than resulting in resets;
* Connection requests to dead ports are blackholed;
* RFC 7323
    * PAWS without fragmentation;
    * Timestamps which are too old;
    * Timestamp rollover;
    * Random timestamp offsets;
* RFC 5961: Challenge Acknowledgments for SYN, RST and data injection attacks;
* No header prediction
* Secure initial sequence number generation
* MD5 authenticated segments when required, with different inbound and outbound keys;
    * Connections requiring MD5 are dropped if segments are unauthenticated;
* Incoming packet reuse to minimize memory overhead;
* Hardware checksum support;
* Zero-Window probe defences (we do not zero-window probe forever, but eventually drop the connection)
    * TODO: Consider changing the zero-window probe logic to time-out after 5 seconds, as longer than this usually indicates a severe problem.


## Constraints

* After 11 zero-window probes (ie we have sent 11 probes) have been sent in a row, we drop the connection without sending a reset;
* After 11 retransmissions (ie we have sent 12 transmissions) have been sent of the same segment, we drop the connection without sending a reset;
* Retransmissions and Zero-Window probes after the 8th are no-longer backed off
* Retransmissions during the SYN_SENT state have a different back-off profile to the norm (but match FreeBSD).
* Minimum retransmission time-out, and initial retransmission time-out is 128ms, not 1sec.
* Maximum retransmission time-out is just over 65 seconds (512 x 128ms).
* Zero-window probe times match retransmission time-outs.


## Performance

* A recent connections cache is used to record congestion-control data to make new connections more efficient, using the principle of "yesterday's weather".


## Limitations

* The use of syncookies means that very large Ethernet Jumbo frames (those over 9000 bytes) are not effectively used for IPV6 TCP packets.
* Likewise, the use of Ethernet frames over 1500 bytes are not effectively used for IPv4.


## Supported RFCs

* RFC 793
* RFC 879
* RFC 1071
* RFC 1122
* RFC 1323
* RFC 1337
* RFC 1644
* RFC 2018
* RFC 2385
* RFC 2460
* RFC 2581
* RFC 2675
* RFC 2873
* RFC 2988
* RFC 3042
* RFC 3168
* RFC 3390
* RFC 3465
* RFC 3540
* RFC 4015
* RFC 4727
* RFC 4782
* RFC 4821
* RFC 4987
* RFC 5482
* RFC 5562
* RFC 5681
* RFC 5682
* RFC 5925
* RFC 5926
* RFC 5961
* RFC 5962
* RFC 6093
* RFC 6298
* RFC 6526
* RFC 6582
* RFC 6675
* RFC 6691
* RFC 6824
* RFC 6928
* RFC 7323
* RFC 7413
* RFC 8311


### RFC violations

* RFC 793, Page 72: "If the segment acknowledgment is not acceptable, form a reset segment, <SEQ=SEG.ACK><CTL=RST>, and send it". This is violated becase to send a reset is to either reveal to a potential attacker we exist or to inadvertently abort an existing connection because of a spoofed packet.
* RFC 793: We blackhole (ignore) any segments with the `ACK` flag bit set in the `LISTEN` or `SYN-RECEIVED` state as these have no legitimate purpose and normally indicate a scan according to pages 5 & 6 of [A Finite State Machine Model of TCP Connections in the Transport Layer", J. Treurniet and J. H. Lefebvre, 2003](http://cradpdf.drdc-rddc.gc.ca/PDFS/unc25/p520460.pdf).
* RFC 4821: We take the advice given and additionally enforce a lowest advertised MSS option of 984 for IPv4 and 1220 for IPv6. In the absence of an MSS option, we force the default MSS to these values rather than 536.
* RFC 5961 Section 3.2 Page 8: We do not send a 'Challenge ACK' when in the `LISTEN` or `SYN-RECEIVED` state, as to do so may reveal that a syncookie we sent as an initial challenge is **invalid**.
* RFC 6298 Section 2.1: We use an initial minimum of 128 milliseconds OR the most recently cached value if available.
* RFC 6298 Section 2.4: We choose a default minimum of 128 milliseconds rather than one second.
* RFC 6298 Section 5.7: We choose to use 3 × 128 milliseconds rather than 3 seconds.


[tcp-engine]: https://github.com/lemonrock/tcp-engine "tcp-engine GitHub page"
