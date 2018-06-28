# tcp-engine

[tcp-engine] is a rust crate.


## Licensing

The license for this project is AGPL3.


## Security and Robustness Features Supported

* Urgent segments are not permitted;
* Non-zero padding and urgent pointers are disallowed;
* TCP known options are always length checked;
* Push flag is always ignored;
* Invalid flag combinations are blackholed;
* Unusual but valid combinations are blackholed;
* Fixed memory usage at start-up;
* Alarm wheels of fixed size with fixed sized 'ticks' to prevent unbounded and unstable alarm growth;
* SYN flooding defences are permanently on: there is no syncache;
* MSS clamping
    * Connections with a small MSS are refused (usually under 1024 on IPv4 and 1220 on IPv6);
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


## Performance

* A recent connections cache is used to record congestion-control data to make new connections more efficient.


[tcp-engine]: https://github.com/lemonrock/tcp-engine "tcp-engine GitHub page"
