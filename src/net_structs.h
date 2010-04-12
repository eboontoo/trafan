#ifndef TRAFAN_NET_STRUCTS
#define TRAFAN_NET_STRUCTS


/* net__frame::type */
#define NET_FRAME_TYPE__IP		0x0800
#define NET_FRAME_TYPE__ARP		0x0806
#define NET_FRAME_TYPE__RARP		0x8035
#define NET_FRAME_TYPE__IPV6		0x86dd
#define NET_FRAME_TYPE__LOOPBACK	0x9000


/* 2nd OSI level - frame structure. */
struct net__frame {
        uint8	dst[6];
        uint8	src[6];
        uint16	type; 
};



/* IP header - type of service */
/* 0-2 bits */
#define NET_PACKET_TOS_PRECEDENCE__ROUTINE		0x0
#define NET_PACKET_TOS_PRECEDENCE__PRIORITY		0x1
#define NET_PACKET_TOS_PRECEDENCE__IMMEDIATE		0x2
#define NET_PACKET_TOS_PRECEDENCE__FLASH		0x3
#define NET_PACKET_TOS_PRECEDENCE__FLASH_OVERRIDE	0x4
#define NET_PACKET_TOS_PRECEDENCE__CRITIC_ECP		0x5
#define NET_PACKET_TOS_PRECEDENCE__INTERNETWORK_CTRL	0x6
#define NET_PACKET_TOS_PRECEDENCE__NETWORK_CTRL		0x7
/* 3 bit */
#define NET_PACKET_TOS_DELAY__NORMAL		0
#define NET_PACKET_TOS_DELAY__LOW		1
/* 4 bit */
#define NET_PACKET_TOS_THROUGHPUT__NORMAL	0
#define NET_PACKET_TOS_THROUGHPUT__HIGH		1
/* 5 bit */
#define NET_PACKET_TOS_RELIABILITY__NORMAL	0
#define NET_PACKET_TOS_RELIABILITY__HIGH	1
/* 6 bit */
#define NET_PACKET_TOS_MONETARY_COST__NORMAL	0
#define NET_PACKET_TOS_MONETARY_COST__MINIMIZE	1

/* IP header - transport protocol */
#define NET_PACKET_TRANS_PROTO__HOPOPT		0	/* IPv6 Hop-by-Hop option */
#define NET_PACKET_TRANS_PROTO__ICMP		1
#define NET_PACKET_TRANS_PROTO__IGMP		2	/* IGAP, IGMP, RGMP */
#define NET_PACKET_TRANS_PROTO__GGP		3	/* Gateway to Gateway Protocol */
#define NET_PACKET_TRANS_PROTO__IPINIP		4	/* IP in IP encapsulation */
#define NET_PACKET_TRANS_PROTO__ST		5	/* ST, Internet Stream Protocol */
#define NET_PACKET_TRANS_PROTO__TCP		6	/* TCP, Transmission Control Protocol */
#define NET_PACKET_TRANS_PROTO__UCL_CBT		7	/* UCL, CBT */
/* TODO: 
8	EGP, Exterior Gateway Protocol.
9	IGRP, Interior Gateway Routing Protocol.
10	BBN RCC Monitoring.
11	NVP, Network Voice Protocol.
12	PUP.
13	ARGUS.
14	EMCON, Emission Control Protocol.
15	XNET, Cross Net Debugger.
16	Chaos.
17	UDP, User Datagram Protocol.
18	TMux, Transport Multiplexing Protocol.
19	DCN Measurement Subsystems.
20	HMP, Host Monitoring Protocol.
21	Packet Radio Measurement.
22	XEROX NS IDP.
23	Trunk-1.
24	Trunk-2.
25	Leaf-1.
26	Leaf-2.
27	RDP, Reliable Data Protocol.
28	IRTP, Internet Reliable Transaction Protocol.
29	ISO Transport Protocol Class 4.
30	NETBLT, Network Block Transfer.
31	MFE Network Services Protocol.
32	MERIT Internodal Protocol.
33	DCCP, Datagram Congestion Control Protocol.
34	Third Party Connect Protocol.
35	IDPR, Inter-Domain Policy Routing Protocol.
36	XTP, Xpress Transfer Protocol.
37	Datagram Delivery Protocol.
38	IDPR, Control Message Transport Protocol.
39	TP++ Transport Protocol.
40	IL Transport Protocol.
41	IPv6 over IPv4.
42	SDRP, Source Demand Routing Protocol.
43	IPv6 Routing header.
44	IPv6 Fragment header.
45	IDRP, Inter-Domain Routing Protocol.
46	RSVP, Reservation Protocol.
47	GRE, General Routing Encapsulation.
48	DSR, Dynamic Source Routing Protocol.
49	BNA.
50	ESP, Encapsulating Security Payload.
51	AH, Authentication Header.
52	I-NLSP, Integrated Net Layer Security TUBA.
53	SWIPE, IP with Encryption.
54	NARP, NBMA Address Resolution Protocol.
55	Minimal Encapsulation Protocol.
56	TLSP, Transport Layer Security Protocol using Kryptonet key management.
57	SKIP.
58	ICMPv6, Internet Control Message Protocol for IPv6.
MLD, Multicast Listener Discovery.
59	IPv6 No Next Header.
60	IPv6 Destination Options.
61	Any host internal protocol.
62	CFTP.
63	Any local network.
64	SATNET and Backroom EXPAK.
65	Kryptolan.
66	MIT Remote Virtual Disk Protocol.
67	Internet Pluribus Packet Core.
68	Any distributed file system.
69	SATNET Monitoring.
70	VISA Protocol.
71	Internet Packet Core Utility.
72	Computer Protocol Network Executive.
73	Computer Protocol Heart Beat.
74	Wang Span Network.
75	Packet Video Protocol.
76	Backroom SATNET Monitoring.
77	SUN ND PROTOCOL-Temporary.
78	WIDEBAND Monitoring.
79	WIDEBAND EXPAK.
80	ISO-IP.
81	VMTP, Versatile Message Transaction Protocol.
82	SECURE-VMTP
83	VINES.
84	TTP.
85	NSFNET-IGP.
86	Dissimilar Gateway Protocol.
87	TCF.
88	EIGRP.
89	OSPF, Open Shortest Path First Routing Protocol.
MOSPF, Multicast Open Shortest Path First.
90	Sprite RPC Protocol.
91	Locus Address Resolution Protocol.
92	MTP, Multicast Transport Protocol.
93	AX.25.
94	IP-within-IP Encapsulation Protocol.
95	Mobile Internetworking Control Protocol.
96	Semaphore Communications Sec. Pro.
97	EtherIP.
98	Encapsulation Header.
99	Any private encryption scheme.
100	GMTP.
101	IFMP, Ipsilon Flow Management Protocol.
102	PNNI over IP.
103	PIM, Protocol Independent Multicast.
104	ARIS.
105	SCPS.
106	QNX.
107	Active Networks.
108	IPPCP, IP Payload Compression Protocol.
109	SNP, Sitara Networks Protocol.
110	Compaq Peer Protocol.
111	IPX in IP.
112	VRRP, Virtual Router Redundancy Protocol.
113	PGM, Pragmatic General Multicast.
114	any 0-hop protocol.
115	L2TP, Level 2 Tunneling Protocol.
116	DDX, D-II Data Exchange.
117	IATP, Interactive Agent Transfer Protocol.
118	ST, Schedule Transfer.
119	SRP, SpectraLink Radio Protocol.
120	UTI.
121	SMP, Simple Message Protocol.
122	SM.
123	PTP, Performance Transparency Protocol.
124	ISIS over IPv4.
125	FIRE.
126	CRTP, Combat Radio Transport Protocol.
127	CRUDP, Combat Radio User Datagram.
128	SSCOPMCE.
129	IPLT.
130	SPS, Secure Packet Shield.
131	PIPE, Private IP Encapsulation within IP.
132	SCTP, Stream Control Transmission Protocol.
133	Fibre Channel.
134	RSVP-E2E-IGNORE.
135	Mobility Header.
136	UDP-Lite, Lightweight User Datagram Protocol.
137	MPLS in IP.
138	MANET protocols.
139	HIP, Host Identity Protocol.
140	Shim6, Level 3 Multihoming Shim Protocol for IPv6.
141	WESP, Wrapped Encapsulating Security Payload.
142	ROHC, Robust Header Compression.*/


/* 3rd OSI level - packet structure. */
struct net__packet {
	uint8		header_len:4;
	uint8		version:4;
	uint8		type_of_service;
	uint16		total_len;
	uint16		id;
	uint8		flags:3;
	uint16		offset:13;
	uint8		ttl;
	uint8		transport_protocol;
	uint16		crc;
	struct in_addr	src;
	struct in_addr	dst;
};


/* 4th OSI level - segment structure. */
struct net__segment {
	uint16		src;
	uint16		dst;
	uint32		seq;
	uint32		ack;
	uint8		data_offset:4;
	uint8		reserved:4;
	uint8		flags;
	uint16		window;
	uint16		crc;
	uint16		urgent;
};

#endif
