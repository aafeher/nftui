# nftui TODO

## Basic ruleset management

### Tables
- [x] list: Display all tables
- [x] view: Show table details
- [x] edit: Modify table properties
- [x] create: Add a new table
- [x] delete: Remove a table

### Chains
- [x] list: Display all chains
- [x] view: Show chain details
- [x] edit: Modify chain properties (hook, policy, priority)
- [x] create: Add a new chain
- [x] delete: Remove a chain

### Rules
- [x] list: Display all rules in a chain
- [x] view: Show rule details and conditions
- [x] edit: Modify an existing rule
- [x] create: Add a new rule
- [x] delete: Remove a rule
- [x] move (up/down): Reorder rules within a chain

## Rules

- [x] `counter`: Packet and byte counters
- [x] `comment`: Human-readable rule description stored in UserData
- [x] `position`: Rule position (editor + insertion at end / before selected)
- [x] `handle`: Kernel-assigned handle ID (display-only)

### Matches

#### IP
- [x] `dscp`: Differentiated Services Code Point
- [x] `length`: Total packet length
- [x] `id`: IP ID
- [x] `frag-off`: Fragmentation offset
- [x] `ttl`: Time to live
- [x] `protocol`: Upper layer protocol
- [x] `checksum`: IP header checksum
- [x] `saddr`: Source address
- [x] `daddr`: Destination address
- [x] `version`: IP header version
- [x] `hdrlength`: IP header length

#### IP6
- [x] `dscp`: Differentiated Services Code Point
- [x] `flowlabel`: Flow label
- [x] `length`: Payload length
- [x] `nexthdr`: Next header type
- [x] `hoplimit`: Hop limit
- [x] `saddr`: Source address
- [x] `daddr`: Destination address
- [x] `version`: IP header version

#### TCP
- [x] `dport`: Destination port
- [x] `sport`: Source port
- [x] `sequence`: Sequence number
- [x] `ackseq`: Acknowledgement number
- [x] `flags`: TCP flags
- [x] `window`: Window
- [x] `checksum`: TCP checksum
- [x] `urgptr`: Urgent pointer
- [x] `doff`: Data offset

#### UDP
- [x] `dport`: Destination port
- [x] `sport`: Source port
- [x] `length`: Total packet length
- [x] `checksum`: UDP checksum

#### UDPLite
- [x] `dport`: Destination port (shared with TCP/UDP wire layout)
- [x] `sport`: Source port (shared with TCP/UDP wire layout)
- [x] `checksum`: UDP checksum (shared with UDP wire layout)

#### SCTP
- [x] `dport`: Destination port
- [x] `sport`: Source port
- [x] `checksum`: Checksum
- [x] `vtag`: Verification tag
- [ ] `chunk`: SCTP chunk (deferred — chunk-type-scoped UX)

#### Dccp
- [x] `dport`: Destination port
- [x] `sport`: Source port
- [x] `type`: Type of packet

#### Ah
- [x] `hdrlength`: AH header length
- [x] `reserved`: Reserved field
- [x] `spi`: Security Parameters Index
- [x] `sequence`: Sequence number

#### Esp
- [x] `spi`: Security Parameters Index
- [x] `sequence`: Sequence number

#### Comp
- [x] `nexthdr`: Next header protocol
- [x] `flags`: Flags
- [x] `cpi`: Compression Parameter Index

#### ICMP
- [x] `type`: ICMP packet type
- [x] `code`: ICMP packet code
- [x] `checksum`: ICMP packet checksum
- [x] `id`: ICMP packet ID
- [x] `sequence`: ICMP packet sequence
- [x] `mtu`: ICMP packet MTU
- [x] `gateway`: ICMP packet gateway

#### ICMPv6
- [x] `type`: ICMPv6 packet type
- [x] `code`: ICMPv6 packet code
- [x] `checksum`: ICMPv6 packet checksum
- [x] `id`: ICMPv6 packet ID
- [x] `sequence`: ICMPv6 packet sequence
- [x] `mtu`: ICMPv6 packet MTU
- [x] `max-delay`: ICMPv6 packet max delay

#### Ethernet (Ether)
- [ ] `saddr`: Source MAC address
- [ ] `type`: EtherType

#### Dst
- [ ] `nexthdr`: Next protocol header
- [ ] `hdrlength`: Header length

#### Frag
- [ ] `nexthdr`: Next protocol header
- [ ] `reserved`: Reserved field
- [ ] `frag-off`: Fragment offset
- [ ] `more-fragments`: More fragments flag
- [ ] `id`: Fragment identification number

#### Hbh
- [ ] `nexthdr`: Next protocol header
- [ ] `hdrlength`: Header length

#### Mh
- [ ] `nexthdr`: Next protocol header
- [ ] `hdrlength`: Header length
- [ ] `type`: Mobility header type
- [ ] `reserved`: Reserved field
- [ ] `checksum`: Mobility header checksum

#### Rt
- [ ] `nexthdr`: Next protocol header
- [ ] `hdrlength`: Header length
- [ ] `type`: Routing header type
- [ ] `seg-left`: Number of route segments remaining

#### Vlan
- [ ] `id`: VLAN tag ID (0–4095)
- [ ] `cfi`: Canonical Format Indicator bit
- [ ] `pcp`: Priority Code Point (0–7)

#### Arp
- [ ] `ptype`: Payload (protocol) type
- [ ] `htype`: Hardware type
- [ ] `hlen`: Hardware address length
- [ ] `plen`: Protocol address length
- [ ] `operation`: ARP operation (request/reply)

#### Ct
- [x] `state`: State of the connection
- [x] `direction`: Direction of the packet relative to the connection
- [x] `status`: Status of the connection
- [x] `mark`: Mark of the connection
- [x] `expiration`: Connection expiration time
- [x] `helper`: Helper associated with the connection
- [x] `bytes`: Number of bytes transferred in the connection (with optional direction)
- [x] `packets`: Number of packets transferred in the connection (with optional direction)
- [x] `ip saddr`: Source IP address of the connection
- [x] `ip daddr`: Destination IP address of the connection
- [x] `l3proto`: Layer 3 protocol (e.g. ipv4, ipv6)
- [x] `protocol`: Layer 4 protocol (e.g. tcp, udp)
- [x] `proto-src`: Source port/ID of the connection
- [x] `proto-dst`: Destination port/ID of the connection
- [x] `zone`: Connection tracking zone ID
- [x] `secmark`: Security mark
- [x] `avgpkt`: Average bytes per packet
- [x] `label`: Connection tracking labels
- [x] `eventmask`: Connection event mask
- [x] `count`: Number of connections matching this rule (ct count)

#### Meta
- [x] `iifname`: Input interface name
- [x] `oifname`: Output interface name
- [x] `iif`: Input interface index
- [x] `oif`: Output interface index
- [x] `iiftype`: Input interface type
- [x] `oiftype`: Output interface hardware type
- [x] `length`: Length of the packet in bytes
- [x] `protocol`: EtherType protocol
- [x] `nfproto`: Netfilter protocol family (ipv4/ipv6)
- [x] `l4proto`: Layer 4 protocol (tcp/udp/icmp etc.)
- [x] `mark`: Packet mark
- [x] `priority`: tc class id
- [x] `skuid`: UID associated with originating socket
- [x] `skgid`: GID associated with originating socket
- [x] `rtclassid`: Routing realm
- [x] `pkttype`: Packet type
- [x] `cpu`: CPU ID
- [x] `iifgroup`: Input interface group
- [x] `oifgroup`: Output interface group
- [x] `cgroup`: Control group ID of the originating process

### Statements

#### Verdict statements
- [x] `accept`: Accept the packet
- [x] `drop`: Drop the packet silently
- [x] `return`: Return to the calling chain
- [x] `jump`: Jump to another chain (return after)
- [x] `goto`: Go to another chain (no return)

#### Log
- [x] `level`: Log level (emerg/alert/crit/err/warn/notice/info/debug)
- [x] `group`: NFLOG group number for userspace logging
- [x] `prefix`: Log message prefix string
- [x] `snaplen`: Number of bytes to copy to userspace
- [x] `queue-threshold`: Number of packets before sending to userspace

#### Reject
- [x] `with icmp type`: Reject with specific ICMP type
- [x] `with icmpx type`: Reject with inet-family ICMP type
- [x] `with tcp reset`: Reject TCP connection with RST

#### Counter
- [x] `packets`: Display/edit packet count
- [x] `bytes`: Display/edit byte count

#### Limit
- [x] `over`: Invert match (match if rate is exceeded)
- [x] `rate`: Rate value
- [x] `unit`: Rate time unit (second/minute/hour/day/week)
- [x] `burst`: Burst size
- [x] `type`: Limit type (packets/bytes)

#### Nat
- [x] `dnat to`: Destination address translation
- [x] `snat to`: Source address translation
- [x] `masquerade`: Masquerade (dynamic SNAT to outgoing interface address)

#### Queue
- [x] `num`: Queue number or range to send packets to userspace

#### Quota
- [x] `[over] <n> [bytes|kbytes|mbytes]`: Quota-based rate limiting
