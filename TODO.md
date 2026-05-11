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
- [ ] create: Add a new chain
- [ ] delete: Remove a chain

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

### Matches

#### IP
- [ ] `dscp`: Differentiated Services Code Point
- [ ] `length`: Total packet length
- [ ] `id`: IP ID
- [ ] `frag-off`: Fragmentation offset
- [ ] `ttl`: Time to live
- [ ] `protocol`: Upper layer protocol
- [ ] `checksum`: IP header checksum
- [x] `saddr`: Source address
- [x] `daddr`: Destination address
- [ ] `version`: IP header version
- [ ] `hdrlength`: IP header length

#### IP6
- [ ] `dscp`: Differentiated Services Code Point
- [ ] `flowlabel`: Flow label
- [ ] `length`: Payload length
- [ ] `nexthdr`: Next header type
- [ ] `hoplimit`: Hop limit
- [ ] `saddr`: Source address
- [ ] `daddr`: Destination address
- [ ] `version`: IP header version

#### TCP
- [ ] `dport`: Destination port
- [ ] `sport`: Source port
- [ ] `sequence`: Sequence number
- [ ] `ackseq`: Acknowledgement number
- [ ] `flags`: TCP flags
- [ ] `window`: Window
- [ ] `checksum`: IP header checksum
- [ ] `urgptr`: Urgent pointer
- [ ] `doff`: Data offset

#### UDP
- [ ] `dport`: Destination port
- [ ] `sport`: Source port
- [ ] `length`: Total packet length
- [ ] `checksum`: UDP checksum

#### UDPLite
- [ ] `dport`: Destination port
- [ ] `sport`: Source port
- [ ] `checksum`: UDP checksum

#### SCTP
- [ ] `dport`: Destination port
- [ ] `sport`: Source port
- [ ] `checksum`: Checksum
- [ ] `vtag`: Verification tag
- [ ] `chunk`: SCTP chunk

#### Dccp
- [ ] `dport`: Destination port
- [ ] `sport`: Source port
- [ ] `type`: Type of packet

#### Ah
- [ ] `hdrlength`: AH header length
- [ ] `reserved`: Reserved field
- [ ] `spi`: Security Parameters Index
- [ ] `sequence`: Sequence number

#### Esp
- [ ] `spi`: Security Parameters Index
- [ ] `sequence`: Sequence number

#### Comp
- [ ] `nexthdr`: Next header protocol
- [ ] `flags`: Flags
- [ ] `cpi`: Compression Parameter Index

#### ICMP
- [ ] `type`: ICMP packet type
- [ ] `code`: ICMP packet code
- [ ] `checksum`: ICMP packet checksum
- [ ] `id`: ICMP packet ID
- [ ] `sequence`: ICMP packet sequence
- [ ] `mtu`: ICMP packet MTU
- [ ] `gateway`: ICMP packet gateway

#### ICMPv6
- [ ] `type`: ICMPv6 packet type
- [ ] `code`: ICMPv6 packet code
- [ ] `checksum`: ICMPv6 packet checksum
- [ ] `id`: ICMPv6 packet ID
- [ ] `sequence`: ICMPv6 packet sequence
- [ ] `mtu`: ICMPv6 packet MTU
- [ ] `max-delay`: ICMPv6 packet max delay

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
- [ ] `secmark`: Security mark
- [x] `avgpkt`: Average bytes per packet
- [x] `label`: Connection tracking labels
- [ ] `eventmask`: Connection event mask
- [x] `count`: Number of connections matching this rule (ct count)

#### Meta
- [ ] `iifname`: Input interface name
- [ ] `oifname`: Output interface name
- [ ] `iif`: Input interface index
- [ ] `oif`: Output interface index
- [ ] `iiftype`: Input interface type
- [ ] `oiftype`: Output interface hardware type
- [ ] `length`: Length of the packet in bytes
- [ ] `protocol`: EtherType protocol
- [ ] `nfproto`: Netfilter protocol family (ipv4/ipv6)
- [ ] `l4proto`: Layer 4 protocol (tcp/udp/icmp etc.)
- [ ] `mark`: Packet mark
- [ ] `priority`: tc class id
- [ ] `skuid`: UID associated with originating socket
- [ ] `skgid`: GID associated with originating socket
- [ ] `rtclassid`: Routing realm
- [ ] `pkttype`: Packet type
- [ ] `cpu`: CPU ID
- [ ] `iifgroup`: Input interface group
- [ ] `oifgroup`: Output interface group
- [ ] `cgroup`: Control group ID of the originating process

### Statements

#### Verdict statements
- [ ] `accept`: Accept the packet
- [ ] `drop`: Drop the packet silently
- [ ] `return`: Return to the calling chain
- [ ] `jump`: Jump to another chain (return after)
- [ ] `goto`: Go to another chain (no return)

#### Log
- [ ] `level`: Log level (emerg/alert/crit/err/warn/notice/info/debug)
- [ ] `group`: NFLOG group number for userspace logging
- [ ] `prefix`: Log message prefix string
- [ ] `snaplen`: Number of bytes to copy to userspace
- [ ] `queue-threshold`: Number of packets before sending to userspace

#### Reject
- [ ] `with icmp type`: Reject with specific ICMP type
- [ ] `with icmpx type`: Reject with inet-family ICMP type
- [ ] `with tcp reset`: Reject TCP connection with RST

#### Counter
- [ ] `packets`: Display/edit packet count
- [ ] `bytes`: Display/edit byte count

#### Limit
- [x] `over`: Invert match (match if rate is exceeded)
- [x] `rate`: Rate value
- [x] `unit`: Rate time unit (second/minute/hour/day/week)
- [x] `burst`: Burst size
- [x] `type`: Limit type (packets/bytes)

#### Nat
- [ ] `dnat to`: Destination address translation
- [ ] `snat to`: Source address translation
- [ ] `masquerade`: Masquerade (dynamic SNAT to outgoing interface address)

#### Queue
- [ ] `num`: Queue number or range to send packets to userspace
