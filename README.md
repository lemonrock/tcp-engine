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
* Segments with an URG flag set or non-zero urgent pointer are considered attacks and blackholed;
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


## Supported & Unsupported Standards


### Supported RFCs (or, where informational, taken note of)

* RFC 8311
* RFC 8087
* RFC 7805
* RFC 7414
* RFC 7323
* RFC 6928
* RFC 6824
* RFC 6691
* RFC 6675
* RFC 6633 (by default as ICMP messages are explicitly not supported)
* RFC 6528
* RFC 6298
* RFC 6247
* RFC 6093 (segments with URG are considered a threat)
* RFC 5961
* RFC 5927 (by default as ICMP messages are explicitly not supported)
* RFC 5681
* RFC 4987
* RFC 4821 (although not PathMTU discovery)
* RFC 4015
* RFC 3540
* RFC 3465
* RFC 3390
* RFC 3360
* RFC 3168
* RFC 3042
* RFC 2988
* RFC 2884
* RFC 2873
* RFC 2675
* RFC 2581
* RFC 2460
* RFC 2416
* RFC 2415
* RFC 2398 (FYI 33)
* RFC 2385 (obsoleted by RFC 5925 but still in widespread use)
* RFC 2151 (FYI 30)
* RFC 2140
* RFC 2018 (but no use is made of SACK blocks)
* RFC 1936
* RFC 1644
* RFC 1624
* RFC 1470 (FYI 2)
* RFC 1323
* RFC 1263
* RFC 1141 (and as updated by RFC 1624)
* RFC 1122
* RFC 1025
* RFC 793
* RFC 792


### Passively Supported RFCs

These are mostly to support passive parsing and validation of options to make sure they are not being used as an attack vector.

* RFC 5926
* RFC 5925
* RFC 5562
* RFC 5482
* RFC 4782
* RFC 4727



### Non-RFC Documents of Significant Merit

* Processing Incoming Segments. This is a markdown document synthesizing many of the RFCs above in to a readable, and referencable, document. Many places in the code reference numbered sections in the generated PDF.
* [Laminar TCP Draft](https://tools.ietf.org/html/draft-mathis-tcpm-tcp-laminar-01). Provides a robust explanation of the subtle meanings of the congestion control variables.
* [A Finite State Machine Model of TCP Connections in the Transport Layer", J. Treurniet and J. H. Lefebvre, 2003](http://cradpdf.drdc-rddc.gc.ca/PDFS/unc25/p520460.pdf). Pages 5 & 6 show a revised state model which makes it clear that many segment flag variations aren't appropriate.


### TODO RFCs

#### SACKs

* RFC 2018 (Selective Acknowledgments)
* RFC 2883 (An Extension to the Selective Acknowledgement (SACK) Option for TCP)


#### Eiffel

* RFC 3522 (The Eifel Detection Algorithm for TCP)
* RFC 4015 (The Eifel Response Algorithm for TCP)


#### Authentication

* RFC 5925 (Authentication)
* RFC 5926 (Authentication)


#### Congestion Control

* RFC 3042 (Enhancing TCP's Loss Recovery Using Limited Transmit)
* RFC 4138 (Forward RTO-Recovery (F-RTO): An Algorithm for Detecting Spurious Retransmission Timeouts with TCP and the Stream Control Transmission Protocol (SCTP))
* RFC 5682 (Forward RTO discovery)
* RFC 6582 (NewReno)
* RFC 6937 (Proportional Rate Reduction (PRR))
* RFC 8257 (Data Centre TCP / Congestion Control)
* Google BBR


#### Other Developments

* RFC 1337 (TIME-WAIT assassination hazards)
* RFC 7413 (TCP Fast Open)
* RFC 4281 (Path MTU discovery)


#### Statistics

* RFC 1155 (MIB)
* RFC 1156 (MIB)
* RFC 4022 (Basic Statistics)
* RFC 4898 (Extended Statistics)


### Explicitly unsupported RFCs

* RFC 8041 (Multipath TCP)
* RFC 7974 (Host identification seems a bad idea)
* RFC 7430 (Multipath TCP)
* RFC 6897 (Multipath TCP)
* RFC 6824 (Multipath TCP)
* RFC 6356 (Multipath TCP)
* RFC 6182 (Multipath TCP)
* RFC 6181 (Multipath TCP)
* RFC 6013 (obsoleted by supported RFC 7805)
* RFC 5841 (April Fool's Day RFC)
* RFC 5562 (not widely supported)
* RFC 4828 (not widely supported)
* RFC 4654 (not widely supported)
* RFC 4614 (obsoleted by RFC 7414)
* RFC 3782 (obsoleted by supported RFC 6582)
* RFC 3540 (made historic by supported RFC 8311)
* RFC 3517 (obsoleted by RFC 6675)
* RFC 3448 (obsoleted by RFC 5348)
* RFC 2861 (obsoleted by RFC 7661)
* RFC 2582 (obsoleted by obsoleted RFC 3782)
* RFC 2581 (obsoleted by supported RFC 5681)
* RFC 2481 (obsoleted by supported RFC 3168)
* RFC 2452 (obsoleted by RFC 4022 and RFC 8096)
* RFC 2414 (obsoleted by RFC 3390)
* RFC 2147 (obsoleted by supported RFC 2675)
* RFC 2012 (obsoleted by RFC 4022)
* RFC 2001 (obsoleted by obsoleted RFC 2581)
* RFC 1948 (obsoleted by supported RFC 6528)
* RFC 1812 (ICMP messages are explicitly not supported)
* RFC 1739 (obsoleted by supported RFC 2151)
* RFC 1716 (obsoleted by explicitly unsupported RFC 1812)
* RFC 1693 (obsoleted by supported RFC 6247)
* RFC 1644 (obsoleted by supported RFC 6247)
* RFC 1379 (obsoleted by supported RFC 6247)
* RFC 1347 (historic predecessor to IPv6)
* RFC 1323 (obsoleted by supported RFC 7323)
* RFC 1185 (obsoleted by obsoleted RFC 1323)
* RFC 1158 (obsoleted by RFC 1213)
* RFC 1147 (obsoleted by RFC 1470)
* RFC 1146 (obsoleted by supported RFC 6247)
* RFC 1145 (obsoleted by supported RFC 6247)
* RFC 1110 (obsoleted by supported RFC 6247)
* RFC 1106 (obsoleted by supported RFC 6247)
* RFC 1095 (obsoleted by RFC 1189)
* RFC 1078 (obsoleted by supported RFC 7805)
* RFC 1072 (obsoleted by supported RFC 6247)
* RFC 1071 (obsoleted by supported RFC 1141)
* RFC 1066 (obsoleted by RFC 1156)
* RFC 1065 (obsoleted by RFC 1155)
* RFC 1011 (URG is explicitly unsupported)
* RFC 1009 (obsoleted by explicitly unsupported RFC 1812)
* RFC 991 (obsoleted by unsupported RFC 1011)
* RFC 964 (made informational by supported RFC 7805)
* RFC 962 (no longer relevant)
* RFC 896 (obsoleted by supported RFC 7805)
* RFC 889 (made informational by supported RFC 7805)
* RFC 879 (obsoleted by supported RFC 7805)
* RFC 872 (made informational by supported RFC 7805)
* RFC 848 (effectively historic)
* RFC 847 (effectively historic)
* RFC 846 (obsoleted by obsoleted RFC 847)
* RFC 845 (obsoleted by obsoleted RFC 846)
* RFC 844 (ICMP messages are explicitly not supported)
* RFC 843 (obsoleted by obsoleted RFC 845)
* RFC 842 (obsoleted by obsoleted RFC 843)
* RFC 839 (obsoleted by obsoleted RFC 842)
* RFC 838 (obsoleted by obsoleted RFC 839)
* RFC 837 (obsoleted by obsoleted RFC 838)
* RFC 836 (obsoleted by obsoleted RFC 837)
* RFC 835 (obsoleted by obsoleted RFC 836)
* RFC 834 (obsoleted by obsoleted RFC 835)
* RFC 833 (obsoleted by obsoleted RFC 834)
* RFC 832 (obsoleted by obsoleted RFC 833)
* RFC 817 (made informational by supported RFC 7805)
* RFC 816 (obsoleted by supported RFC 7805)
* RFC 814 (made informational by supported RFC 7805)
* RFC 813 (obsoleted by supported RFC 7805)
* RFC 794 (made informational by supported RFC 7805)
* RFC 761 (obsoleted by supported RFC 7805)
* RFC 721 (obsoleted by supported RFC 7805)
* RFC 700 (made informational by supported RFC 7805)
* RFC 675 (obsoleted by supported RFC 7805)


### RFCs to explore

* RFC 7661 (Updating TCP to Support Rate-Limited Traffic)
* RFC 7605 (port number recommendations)
* RFC 6335 0-1023         0x0000-0x03FF  System (also Well-Known)
                 1024-49151     0x0400-0xBFFF  User (also Registered)
                 49152-65535    0xC000-0xFFFF  Dynamic (also Private)
RFC 7242
Delay-Tolerant Networking TCP Convergence-Layer Protocol, June 2014

RFC 6994
Shared Use of Experimental TCP Options, August 2013

RFC 6978
A TCP Authentication Option Extension for NAT Traversal, July 2013

RFC 7786
TCP Modifications for Congestion Exposure (ConEx)

BCP 165
RFC 7605
Recommendations on Using Assigned Transport Port Numbers

RFC 6675
A Conservative Loss Recovery Algorithm Based on Selective Acknowledgment (SACK) for TCP
Obsoletes RFC 3517

RFC 6544
TCP Candidates with Interactive Connectivity Establishment (ICE)

RFC 6429
TCP Sender Clarification for Persist Condition, December 2011

RFC 6349
Framework for TCP Throughput Testing (useful information).

BCP 159
RFC 6191
Reducing the TIME-WAIT State Using TCP Timestamps.

RFC 6069
Making TCP More Robust to Long Connectivity Disruptions (TCP-LCD)

RFC 6062
Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations

RFC 5827
Early Retransmit for TCP and Stream Control Transmission Protocol (SCTP)

RFC 5690
Adding Acknowledgement Congestion Control to TCP

RFC 5461
TCP's Reaction to Soft Errors
Uses ICMP so probably should document

BCP 142
RFC 5382
NAT Behavioral Requirements for TCP (updated by RFC 7857)

RFC 5348
TCP Friendly Rate Control (TFRC): Protocol Specification

RFC 4953
Defending TCP Against Spoofing Attacks

RFC 4808
Key Change Strategies for TCP-MD5

RFC 4653
Improving the Robustness of TCP to Non-Congestion Events

RFC 4278
Standards Maturity Variance Regarding the TCP MD5 Signature Option (RFC 2385) and the BGP-4 Specification

RFC 3742
Limited Slow-Start for TCP with Large Congestion Windows

RFC 3708
Using TCP Duplicate Selective Acknowledgement (DSACKs) ... to Detect Spurious Retransmissions,

RFC 3649
HighSpeed TCP for Large Congestion Windows

RFC 3562
Key Management Considerations for the TCP MD5 Signature Option

BCP 69
RFC 3449
TCP Performance Implications of Network Path Asymmetry

RFC 2923
TCP Problems with Path MTU Discovery

RFC 2760
Ongoing TCP Research Related to Satellites

RFC 2757
Long Thin Networks

RFC 2553
Basic Socket Interface Extensions for IPv6

RFC 2525
Known TCP Implementation Problems

BCP 28
RFC 2488
Enhancing TCP Over Satellite Channels using Standard Mechanisms

RFC 3128
Protection Against a Variant of the Tiny Fragment Attack (RFC 1858)
RFC 1858
Security Considerations for IP Fragment Filtering

RFC 1180
TCP/IP tutorial

### RFC violations

ICMP messages are explicitly not supported. In the internet at large, they are often blocked, have been frequently used as attack vectors and are not essential to TCP operation. In practice, only ICMP messages relating to PathMTU discovery and host unreachability are of interest. However, both of these can be used to perform Denial-of-Service or 'Slow' attacks, to both servers and clients, and so we do not make use of them.

* RFC 792: We do not support ICMP messages.
* RFC 793, Page 72: "If the segment acknowledgment is not acceptable, form a reset segment, <SEQ=SEG.ACK><CTL=RST>, and send it". This is violated becase to send a reset is to either reveal to a potential attacker we exist or to inadvertently abort an existing connection because of a spoofed packet.
* RFC 793: We blackhole (ignore) any segments with the `ACK` flag bit set in the `LISTEN` or `SYN-RECEIVED` state as these have no legitimate purpose and normally indicate a scan according to pages 5 & 6 of [A Finite State Machine Model of TCP Connections in the Transport Layer", J. Treurniet and J. H. Lefebvre, 2003](http://cradpdf.drdc-rddc.gc.ca/PDFS/unc25/p520460.pdf).
* RFC 793: URG and the urgent pointer are not appropriate in the modern internet and are considered threats.
* RFC 1122: We do not support ICMP messages.
* RFC 2675: IPv6 Jumbograms are not supported.
* RFC 3360 Section 2.1: We foricbly validate that the reserved field is zero.
* RFC 4821: We take the advice given and additionally enforce a lowest advertised MSS option of 984 for IPv4 and 1220 for IPv6. In the absence of an MSS option, we force the default MSS to these values rather than 536.
* RFC 5961 Section 3.2 Page 8: We do not send a 'Challenge ACK' when in the `LISTEN` or `SYN-RECEIVED` state, as to do so may reveal that a syncookie we sent as an initial challenge is **invalid**.
* RFC 6298 Section 2.1: We use an initial minimum of 128 milliseconds OR the most recently cached value if available.
* RFC 6298 Section 2.4: We choose a default minimum of 128 milliseconds rather than one second.
* RFC 6298 Section 5.7: We choose to use 3 × 128 milliseconds rather than 3 seconds.


[tcp-engine]: https://github.com/lemonrock/tcp-engine "tcp-engine GitHub page"
