# nftui TODO

## Basic ruleset management

### Tables
- [x] list
- [x] view
- [ ] edit
- [ ] create
- [ ] delete

### Chains
- [x] list
- [x] view
- [ ] edit
- [ ] create
- [ ] delete

### Rules
- [x] list
- [x] view
- [x] edit
- [ ] create
- [ ] delete
- [ ] move (up/down)

## Rules

- [x] `counter`
- [x] `comment`

### Matches

#### IP
- [ ] `dscp`: Differentiated Services Code Point
- [ ] `length`: Total packet length
- [ ] `id`: IP ID
- [ ] `frag-off`: Fragmentation offset
- [ ] `ttl`: Time to live
- [ ] `protocol`: Upper layer protocol
- [ ] `checksum`: IP header checksum
- [ ] `saddr`: Source address
- [ ] `daddr`: Destination address
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
- [ ] `reservded`:
- [ ] `spi`:
- [ ] `sequence`: Sequence number

#### Esp
- [ ] `spi`:
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
- [ ] `reserved`
- [ ] `frag-off`
- [ ] `more-fragments`
- [ ] `id`

#### Hbh
- [ ] `nexthdr`: Next protocol header
- [ ] `hdrlength`: Header length

#### Mh
- [ ] `nexthdr`: Next protocol header
- [ ] `hdrlength`: Header length
- [ ] `type`
- [ ] `reserved`
- [ ] `checksum`

#### Rt
- [ ] `nexthdr`: Next protocol header
- [ ] `hdrlength`: Header length
- [ ] `type`
- [ ] `seg-left`

#### Vlan
- [ ] `id`: Vlan tag ID
- [ ] `cfi`
- [ ] `pcp`

#### Arp
- [ ] `ptype`: Payload type
- [ ] `htype`: Header type
- [ ] `hlen`: Header length
- [ ] `plen`: Payload length
- [ ] `operation`

#### Ct
- [x] `state`: State of the connection
- [x] `direction`: Direction of the packet relative to the connection
- [x] `status`: Status of the connection
- [x] `mark`: Mark of the connection
- [x] `expiration`: Connection expiration time
- [x] `helper`: Helper associated with the connection
- [x] `bytes`
- [ ] `packets`
- [ ] `ip saddr`
- [ ] `ip daddr`
- [ ] `l3proto`
- [ ] `protocol`
- [ ] `proto-dst`
- [ ] `proto-src`
- [ ] `count`

#### Meta
- [ ] `iifname`: Input interface name
- [ ] `oifname`: Output interface name
- [ ] `iif`: Input interface index
- [ ] `oif`: Output interface index
- [ ] `iiftype`: Input interface type
- [ ] `oiftype`: Output interface hardware type
- [ ] `length`: Length of the packet in bytes
- [ ] `protocol`: EtherType protocol
- [ ] `nfproto`
- [ ] `l4proto`
- [ ] `mark`: Packet mark
- [ ] `priority`: tc class id
- [ ] `skuid`: UID associated with originating socket
- [ ] `skgid`: GID associated with originating socket
- [ ] `rtclassid`: Routing realm
- [ ] `pkttype`: Packet type
- [ ] `cpu`: CPU ID
- [ ] `iifgroup`: Input interface group
- [ ] `oifgroup`: Output interface group
- [ ] `cgroup`

### Statements

#### Verdict statements

#### Log
- [ ] `level`: Log level
- [ ] `group`

#### Reject
- [ ] `with`
- [ ] `type`

#### Counter
- [ ] `packets`
- [ ] `bytes`

#### Limit
- [x] `over`
- [x] `rate`
- [x] `unit`
- [x] `burst`
- [x] `type`

#### Nat
- [ ] `dnat to`: Destination address translation
- [ ] `snat to`: Source address translation
- [ ] `masquerade`: Masquerade

#### Queue
- [ ] `num`
