#include "../header.h"
#include <assert.h>
#include <dirent.h>

static int count_open_fds(void)
{
	DIR* d = opendir("/proc/self/fd");
	assert(d != NULL);
	int n = 0;
	while (readdir(d) != NULL)
		n++;
	closedir(d);
	return n;
}

static uint16_t verify_ip_sum(const Packet* pip)
{
	uint16_t len = (uint16_t)((pip->verihl & 0x0F) << 2);
	const uint8_t* b = (const uint8_t*)pip;
	uint32_t s = 0;
	for (size_t i = 0; i < len; i += 2) {
		uint16_t w = 0;
		memcpy(&w, b + i, 2);
		s += w;
		if (s & 0xFFFF0000) { s = (s & 0xFFFF) + 1; }
	}
	return (uint16_t)(~(s & 0xFFFF));
}

static size_t build_tcp_frame(uint8_t* buf,
                              const uint8_t src_mac[6], const uint8_t dst_mac[6],
                              const uint8_t src_ip[4], const uint8_t dst_ip[4],
                              uint16_t sport_h, uint16_t dport_h, uint8_t flags6,
                              const char* payload)
{
	size_t plen = payload ? strlen(payload) : 0;
	size_t ip_len = sizeof(Packet) + sizeof(Segment) + plen;
	size_t total = sizeof(Frame) + ip_len;
	memset(buf, 0, total);

	Frame* eth = (Frame*)buf;
	memcpy(eth->dstMac, dst_mac, 6);
	memcpy(eth->srcMac, src_mac, 6);
	eth->protocol = htons(ETH_P_IP);

	Packet* pip = (Packet*)(buf + sizeof(Frame));
	pip->verihl = 0x45;
	pip->length = htons((uint16_t)ip_len);
	pip->ttl = 64;
	pip->protocol = IPPROTO_TCP;
	memcpy(pip->srcip, src_ip, 4);
	memcpy(pip->dstip, dst_ip, 4);
	pip->checksum = packet_checksum(pip);

	Segment* ptcp = (Segment*)(buf + sizeof(Frame) + sizeof(Packet));
	ptcp->srcport = htons(sport_h);
	ptcp->dstport = htons(dport_h);
	ptcp->seq = htonl(1000);
	ptcp->ack = htonl(0);
	ptcp->flags = htons((uint16_t)((5u << 12) | (flags6 & 0x3F)));
	ptcp->window = htons(65535);
	if (plen > 0)
		memcpy((uint8_t*)ptcp + sizeof(Segment), payload, plen);
	ptcp->checksum = segment_checksum(pip, ptcp);
	return total;
}

static size_t build_udp_frame(uint8_t* buf,
                              const uint8_t src_mac[6], const uint8_t dst_mac[6],
                              const uint8_t src_ip[4], const uint8_t dst_ip[4],
                              uint16_t sport_h, uint16_t dport_h,
                              const char* payload)
{
	size_t plen = payload ? strlen(payload) : 0;
	size_t udp_len = sizeof(UdpHeader) + plen;
	size_t ip_len = sizeof(Packet) + udp_len;
	size_t total = sizeof(Frame) + ip_len;
	memset(buf, 0, total);

	Frame* eth = (Frame*)buf;
	memcpy(eth->dstMac, dst_mac, 6);
	memcpy(eth->srcMac, src_mac, 6);
	eth->protocol = htons(ETH_P_IP);

	Packet* pip = (Packet*)(buf + sizeof(Frame));
	pip->verihl = 0x45;
	pip->length = htons((uint16_t)ip_len);
	pip->ttl = 64;
	pip->protocol = IPPROTO_UDP;
	memcpy(pip->srcip, src_ip, 4);
	memcpy(pip->dstip, dst_ip, 4);
	pip->checksum = packet_checksum(pip);

	UdpHeader* pudp = (UdpHeader*)(buf + sizeof(Frame) + sizeof(Packet));
	pudp->srcport = htons(sport_h);
	pudp->dstport = htons(dport_h);
	pudp->length = htons((uint16_t)udp_len);
	if (plen > 0)
		memcpy((uint8_t*)pudp + sizeof(UdpHeader), payload, plen);
	pudp->checksum = udp_checksum(pip, pudp);
	return total;
}

static size_t build_icmp_frame(uint8_t* buf,
                               const uint8_t src_mac[6], const uint8_t dst_mac[6],
                               const uint8_t src_ip[4], const uint8_t dst_ip[4],
                               uint8_t type, uint16_t id_h, uint16_t seq_h,
                               const char* payload)
{
	size_t plen = payload ? strlen(payload) : 0;
	size_t icmp_len = sizeof(IcmpHeader) + plen;
	size_t ip_len = sizeof(Packet) + icmp_len;
	size_t total = sizeof(Frame) + ip_len;
	memset(buf, 0, total);

	Frame* eth = (Frame*)buf;
	memcpy(eth->dstMac, dst_mac, 6);
	memcpy(eth->srcMac, src_mac, 6);
	eth->protocol = htons(ETH_P_IP);

	Packet* pip = (Packet*)(buf + sizeof(Frame));
	pip->verihl = 0x45;
	pip->length = htons((uint16_t)ip_len);
	pip->ttl = 64;
	pip->protocol = IPPROTO_ICMP;
	memcpy(pip->srcip, src_ip, 4);
	memcpy(pip->dstip, dst_ip, 4);
	pip->checksum = packet_checksum(pip);

	IcmpHeader* picmp = (IcmpHeader*)(buf + sizeof(Frame) + sizeof(Packet));
	picmp->type = type;
	picmp->code = 0;
	picmp->id = htons(id_h);
	picmp->seq = htons(seq_h);
	if (plen > 0)
		memcpy((uint8_t*)picmp + sizeof(IcmpHeader), payload, plen);
	picmp->checksum = icmp_checksum((const uint8_t*)picmp, icmp_len);
	return total;
}

int main(void)
{
	const uint8_t lan_mac[6]    = {0x88, 0xa2, 0x9e, 0x70, 0x00, 0x39};
	const uint8_t wan_mac[6]    = {0x88, 0xa2, 0x9e, 0x70, 0x00, 0x3a};
	const uint8_t gw_mac[6]     = {0xfe, 0xd8, 0x3e, 0x95, 0x59, 0xef};
	const uint8_t jetson_mac[6] = {0xac, 0x3a, 0xe2, 0x7c, 0x22, 0xe9};
	const uint8_t client_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

	const uint8_t lan_ip[4]     = {192, 168, 100, 1};
	const uint8_t jetson_ip[4]  = {192, 168, 100, 2};
	const uint8_t wan_ip[4]     = {10, 68, 253, 114};
	const uint8_t ext_dns[4]    = {8, 8, 8, 8};
	const uint8_t ext_web[4]    = {1, 1, 1, 1};
	const uint8_t wifi_cli[4]   = {10, 68, 253, 50};

	RouterConfig cfg = {0};
	pthread_mutex_init(&cfg.fwd_lock, NULL);
	strcpy(cfg.lan_if, "eth0");
	strcpy(cfg.wan_if, "wlan0");
	memcpy(cfg.lan_mac, lan_mac, 6);
	memcpy(cfg.lan_ip, lan_ip, 4);
	cfg.has_lan_ip = 1;
	memcpy(cfg.wan_mac, wan_mac, 6);
	memcpy(cfg.wan_ip, wan_ip, 4);
	memcpy(cfg.gw_mac, gw_mac, 6);
	cfg.has_wan_l3 = 1;
	cfg.has_port_fwd = 1;
	memcpy(cfg.fwd_lan_ip, jetson_ip, 4);
	memcpy(cfg.fwd_lan_mac, jetson_mac, 6);
	cfg.has_fwd_lan_mac = 1;
	cfg.fwd_wan_port = htons(25000);
	cfg.fwd_lan_port = htons(25000);

	table tbl;
	nat_table_init(&tbl);

	uint8_t buf[2048];

	/* 1. Outbound TCP SNAT + Inbound TCP DNAT & safe port pool check */
	size_t len = build_tcp_frame(buf, jetson_mac, lan_mac, jetson_ip, ext_web, 51234, 443, TCP_FLAG_SYN, "GET");
	assert(nat_outbound_snat(&cfg, &tbl, buf, len) == 0);
	Packet* pip = (Packet*)(buf + sizeof(Frame));
	Segment* ptcp = (Segment*)(buf + sizeof(Frame) + sizeof(Packet));
	Frame* eth = (Frame*)buf;
	uint16_t nat_tcp_port = ntohs(ptcp->srcport);
	assert(nat_tcp_port >= NAT_PORT_MIN && nat_tcp_port <= NAT_PORT_MAX);
	assert(nat_tcp_port != 25000 && nat_tcp_port < 32768);
	assert(memcmp(pip->srcip, wan_ip, 4) == 0);
	assert(pip->ttl == 63);
	assert(verify_ip_sum(pip) == 0);
	assert(ptcp->checksum == segment_checksum(pip, ptcp));
	assert(memcmp(eth->srcMac, wan_mac, 6) == 0 && memcmp(eth->dstMac, gw_mac, 6) == 0);

	len = build_tcp_frame(buf, gw_mac, wan_mac, ext_web, wan_ip, 443, nat_tcp_port, TCP_FLAG_SYN | TCP_FLAG_ACK, "OK!");
	assert(nat_inbound_dnat(&cfg, &tbl, buf, len) == 0);
	pip = (Packet*)(buf + sizeof(Frame));
	ptcp = (Segment*)(buf + sizeof(Frame) + sizeof(Packet));
	eth = (Frame*)buf;
	assert(memcmp(pip->dstip, jetson_ip, 4) == 0);
	assert(ntohs(ptcp->dstport) == 51234);
	assert(verify_ip_sum(pip) == 0);
	assert(ptcp->checksum == segment_checksum(pip, ptcp));
	assert(memcmp(eth->srcMac, lan_mac, 6) == 0 && memcmp(eth->dstMac, jetson_mac, 6) == 0);
	printf("[PASS] 1. TCP Outbound SNAT + Inbound DNAT (nat_port=%u in safe 26000-31000)\n", nat_tcp_port);

	/* 2. Outbound UDP (DNS:53) SNAT + Inbound UDP DNAT (with odd-length payload) */
	len = build_udp_frame(buf, jetson_mac, lan_mac, jetson_ip, ext_dns, 53001, 53, "dns-q");
	assert(nat_outbound_snat(&cfg, &tbl, buf, len) == 0);
	pip = (Packet*)(buf + sizeof(Frame));
	UdpHeader* pudp = (UdpHeader*)(buf + sizeof(Frame) + sizeof(Packet));
	uint16_t nat_udp_port = ntohs(pudp->srcport);
	assert(nat_udp_port >= NAT_PORT_MIN && nat_udp_port <= NAT_PORT_MAX);
	assert(memcmp(pip->srcip, wan_ip, 4) == 0);
	assert(verify_ip_sum(pip) == 0);
	assert(pudp->checksum == udp_checksum(pip, pudp));

	len = build_udp_frame(buf, gw_mac, wan_mac, ext_dns, wan_ip, 53, nat_udp_port, "dns-resp1");
	assert(nat_inbound_dnat(&cfg, &tbl, buf, len) == 0);
	pip = (Packet*)(buf + sizeof(Frame));
	pudp = (UdpHeader*)(buf + sizeof(Frame) + sizeof(Packet));
	assert(memcmp(pip->dstip, jetson_ip, 4) == 0);
	assert(ntohs(pudp->dstport) == 53001);
	assert(verify_ip_sum(pip) == 0);
	assert(pudp->checksum == udp_checksum(pip, pudp));
	printf("[PASS] 2. UDP (DNS) Outbound SNAT + Inbound DNAT (nat_port=%u)\n", nat_udp_port);

	/* 3. Outbound ICMP Echo Request + Inbound ICMP Echo Reply */
	len = build_icmp_frame(buf, jetson_mac, lan_mac, jetson_ip, ext_dns, 8, 0x1234, 1, "ping-test");
	assert(nat_outbound_snat(&cfg, &tbl, buf, len) == 0);
	pip = (Packet*)(buf + sizeof(Frame));
	IcmpHeader* picmp = (IcmpHeader*)(buf + sizeof(Frame) + sizeof(Packet));
	uint16_t nat_icmp_id = ntohs(picmp->id);
	assert(nat_icmp_id >= NAT_PORT_MIN && nat_icmp_id <= NAT_PORT_MAX);
	assert(verify_ip_sum(pip) == 0);
	assert(picmp->checksum == icmp_checksum((const uint8_t*)picmp, ntohs(pip->length) - sizeof(Packet)));

	len = build_icmp_frame(buf, gw_mac, wan_mac, ext_dns, wan_ip, 0, nat_icmp_id, 1, "ping-test");
	assert(nat_inbound_dnat(&cfg, &tbl, buf, len) == 0);
	pip = (Packet*)(buf + sizeof(Frame));
	picmp = (IcmpHeader*)(buf + sizeof(Frame) + sizeof(Packet));
	assert(memcmp(pip->dstip, jetson_ip, 4) == 0);
	assert(ntohs(picmp->id) == 0x1234);
	assert(verify_ip_sum(pip) == 0);
	assert(picmp->checksum == icmp_checksum((const uint8_t*)picmp, ntohs(pip->length) - sizeof(Packet)));
	printf("[PASS] 3. ICMP (ping) Outbound SNAT + Inbound DNAT (nat_id=%u)\n", nat_icmp_id);

	/* 4. Port Forwarding WAN:25000 -> Jetson 192.168.100.2:25000 + Reply SNAT */
	len = build_tcp_frame(buf, client_mac, wan_mac, wifi_cli, wan_ip, 49152, 25000, TCP_FLAG_SYN, NULL);
	assert(nat_inbound_dnat(&cfg, &tbl, buf, len) == 0);
	pip = (Packet*)(buf + sizeof(Frame));
	ptcp = (Segment*)(buf + sizeof(Frame) + sizeof(Packet));
	eth = (Frame*)buf;
	assert(memcmp(pip->dstip, jetson_ip, 4) == 0);
	assert(ntohs(ptcp->dstport) == 25000);
	assert(memcmp(eth->srcMac, lan_mac, 6) == 0 && memcmp(eth->dstMac, jetson_mac, 6) == 0);
	assert(verify_ip_sum(pip) == 0 && ptcp->checksum == segment_checksum(pip, ptcp));

	/* Jetson replies from 192.168.100.2:25000 -> 10.68.253.50:49152 */
	len = build_tcp_frame(buf, jetson_mac, lan_mac, jetson_ip, wifi_cli, 25000, 49152, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL);
	assert(nat_outbound_snat(&cfg, &tbl, buf, len) == 0);
	pip = (Packet*)(buf + sizeof(Frame));
	ptcp = (Segment*)(buf + sizeof(Frame) + sizeof(Packet));
	eth = (Frame*)buf;
	assert(memcmp(pip->srcip, wan_ip, 4) == 0);
	assert(ntohs(ptcp->srcport) == 25000); /* MUST stay 25000, NOT randomized! */
	assert(memcmp(eth->srcMac, wan_mac, 6) == 0 && memcmp(eth->dstMac, client_mac, 6) == 0);
	assert(verify_ip_sum(pip) == 0 && ptcp->checksum == segment_checksum(pip, ptcp));
	printf("[PASS] 4. Port Forwarding WAN:25000 <-> Jetson:25000 (port & peer_mac preserved)\n");

	/* 5. LAN-local SSH (192.168.100.1) & multicast/broadcast exclusion */
	const uint8_t mcast_ip[4] = {224, 0, 0, 251};
	const uint8_t bcast_ip[4] = {192, 168, 100, 255};
	len = build_tcp_frame(buf, jetson_mac, lan_mac, jetson_ip, lan_ip, 50000, 22, TCP_FLAG_SYN, NULL);
	assert(nat_outbound_snat(&cfg, &tbl, buf, len) == 1);
	len = build_udp_frame(buf, jetson_mac, lan_mac, jetson_ip, mcast_ip, 5353, 5353, "mdns");
	assert(nat_outbound_snat(&cfg, &tbl, buf, len) == 1);
	len = build_udp_frame(buf, jetson_mac, lan_mac, jetson_ip, bcast_ip, 68, 67, "bc");
	assert(nat_outbound_snat(&cfg, &tbl, buf, len) == 1);
	printf("[PASS] 5. Local LAN (192.168.100.1) & multicast/broadcast excluded from WAN NAT\n");

	/* 6. Real Multi-Threaded IDS Worker Thread + PacketQueue Test */
	const char* test_log = "/tmp/test_ids_verify.log";
	remove(test_log);

	RouterConfig worker_cfg = cfg;
	pthread_mutex_init(&worker_cfg.fwd_lock, NULL);
	worker_cfg.has_wan_l3 = 0; /* record allowed sessions into table without calling sendto */

	table worker_tbl;
	nat_table_init(&worker_tbl);

	IDSContext ids_ctx;
	assert(ids_init(&ids_ctx, test_log) == 0);

	PacketQueue* q = calloc(1, sizeof(PacketQueue));
	assert(q != NULL);
	pkt_queue_init(q);

	WorkerArg warg = {0};
	warg.hsock = -1;
	warg.cfg = &worker_cfg;
	warg.nat_table = &worker_tbl;
	warg.ids_ctx = &ids_ctx;
	warg.queue = q;

	pthread_t tid;
	assert(pthread_create(&tid, NULL, ids_worker_thread, &warg) == 0);

	time_t now = time(NULL);

	/* 6a. Legitimate SYN -> MUST pass IDS thread and enter NAT table */
	len = build_tcp_frame(buf, jetson_mac, lan_mac, jetson_ip, ext_web, 55001, 443, TCP_FLAG_SYN, NULL);
	assert(pkt_queue_push(q, buf, len, 1, now) == 0);

	/* 6b. NULL scan -> MUST be dropped by IDS thread */
	const uint8_t atk1[4] = {10, 68, 253, 91};
	len = build_tcp_frame(buf, client_mac, wan_mac, atk1, wan_ip, 12345, 25000, 0, NULL);
	assert(pkt_queue_push(q, buf, len, 0, now) == 0);

	/* 6c. Xmas scan (FIN+PSH+URG) -> MUST be dropped */
	len = build_tcp_frame(buf, client_mac, wan_mac, atk1, wan_ip, 12346, 25000,
	                      TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG, NULL);
	assert(pkt_queue_push(q, buf, len, 0, now) == 0);

	/* 6d. LAND attack (srcip == dstip) -> MUST be dropped */
	len = build_tcp_frame(buf, client_mac, wan_mac, wan_ip, wan_ip, 25000, 25000, TCP_FLAG_SYN, NULL);
	assert(pkt_queue_push(q, buf, len, 0, now) == 0);

	/* 6e. SYN+FIN invalid flags -> MUST be dropped */
	len = build_tcp_frame(buf, client_mac, wan_mac, atk1, wan_ip, 12347, 25000,
	                      TCP_FLAG_SYN | TCP_FLAG_FIN, NULL);
	assert(pkt_queue_push(q, buf, len, 0, now) == 0);

	/* 6f. Port Scan (20 distinct ports from atk2) -> 20th packet MUST be dropped */
	const uint8_t atk2[4] = {10, 68, 253, 92};
	for (uint16_t p = 1000; p < 1020; p++) {
		len = build_tcp_frame(buf, client_mac, wan_mac, atk2, wan_ip, 40000 + p, p, TCP_FLAG_SYN, NULL);
		assert(pkt_queue_push(q, buf, len, 0, now) == 0);
	}

	/* 6g. SYN Flood (>50 SYNs to same port from atk3) -> 51st packet MUST be dropped */
	const uint8_t atk3[4] = {10, 68, 253, 93};
	for (int i = 0; i < 52; i++) {
		len = build_tcp_frame(buf, client_mac, wan_mac, atk3, wan_ip, (uint16_t)(30000 + i), 25000, TCP_FLAG_SYN, NULL);
		assert(pkt_queue_push(q, buf, len, 0, now) == 0);
	}

	pkt_queue_stop(q);
	pthread_join(tid, NULL);

	/* Only the 1 legitimate LAN->WAN SYN should have been added to worker_tbl */
	assert(worker_tbl.size == 1);

	ids_destroy(&ids_ctx);
	pkt_queue_destroy(q);
	free(q);
	destroy(&worker_tbl);
	destroy(&tbl);

	/* Verify IDS log recorded all 6 attack categories */
	FILE* fp = fopen(test_log, "r");
	assert(fp != NULL);
	char log_content[8192] = {0};
	size_t nread = fread(log_content, 1, sizeof(log_content) - 1, fp);
	fclose(fp);
	assert(nread > 0);
	assert(strstr(log_content, "TCP NULL scan") != NULL);
	assert(strstr(log_content, "TCP Xmas scan") != NULL);
	assert(strstr(log_content, "LAND attack") != NULL);
	assert(strstr(log_content, "SYN+FIN") != NULL);
	assert(strstr(log_content, "TCP Port Scan detected") != NULL);
	assert(strstr(log_content, "TCP SYN Flood detected") != NULL);
	remove(test_log);

	printf("[PASS] 6. Dedicated IDS Worker Thread + PacketQueue verified (NULL/Xmas/LAND/SYN+FIN/PortScan/SYNFlood all dropped & logged; legitimate SYN allowed)\n");

	/* 7. Built-in RFC 2131 LAN DHCPv4 Server Protocol Verification */
	DHCPServerState dhcp;
	dhcp_state_init(&dhcp, lan_ip);

	RouterConfig dhcp_cfg = {0};
	pthread_mutex_init(&dhcp_cfg.fwd_lock, NULL);
	dhcp_cfg.has_port_fwd = 1;
	memcpy(dhcp_cfg.fwd_lan_ip, jetson_ip, 4);
	dhcp_cfg.has_fwd_lan_mac = 0;

	DHCPPacket req = {0};
	uint8_t resp_raw[sizeof(DHCPPacket)];
	int send_bcast = 0;
	uint8_t ucast_ip[4] = {0};

	/* 7a. DISCOVER from Jetson MAC -> OFFER 192.168.100.2 */
	req.op = 1; req.htype = 1; req.hlen = 6;
	req.xid = htonl(0x11223344u);
	memcpy(req.chaddr, jetson_mac, 6);
	req.magic = htonl(DHCP_MAGIC_COOKIE);
	size_t o = 0;
	req.options[o++] = 53; req.options[o++] = 1; req.options[o++] = DHCP_MSG_DISCOVER;
	req.options[o++] = 255;

	ssize_t rlen = dhcp_handle_request(&dhcp, &dhcp_cfg, (const uint8_t*)&req,
	                                   offsetof(DHCPPacket, options) + o,
	                                   resp_raw, sizeof(resp_raw), &send_bcast, ucast_ip);
	assert(rlen >= 300);
	const DHCPPacket* resp = (const DHCPPacket*)resp_raw;
	assert(resp->op == 2 && resp->xid == req.xid);
	assert(memcmp(&resp->yiaddr, jetson_ip, 4) == 0);
	assert(memcmp(&resp->siaddr, lan_ip, 4) == 0);
	assert(send_bcast == 1);
	assert(resp->options[0] == 53 && resp->options[1] == 1 && resp->options[2] == DHCP_MSG_OFFER);

	/* 7b. REQUEST 192.168.100.2 -> ACK + auto-sync port-forward MAC */
	o = 0;
	req.options[o++] = 53; req.options[o++] = 1; req.options[o++] = DHCP_MSG_REQUEST;
	req.options[o++] = 50; req.options[o++] = 4; memcpy(req.options + o, jetson_ip, 4); o += 4;
	req.options[o++] = 54; req.options[o++] = 4; memcpy(req.options + o, lan_ip, 4); o += 4;
	req.options[o++] = 255;
	rlen = dhcp_handle_request(&dhcp, &dhcp_cfg, (const uint8_t*)&req,
	                           offsetof(DHCPPacket, options) + o,
	                           resp_raw, sizeof(resp_raw), &send_bcast, ucast_ip);
	assert(rlen >= 300);
	assert(resp->options[0] == 53 && resp->options[1] == 1 && resp->options[2] == DHCP_MSG_ACK);
	assert(memcmp(&resp->yiaddr, jetson_ip, 4) == 0);
	assert(dhcp_cfg.has_fwd_lan_mac == 1 && memcmp(dhcp_cfg.fwd_lan_mac, jetson_mac, 6) == 0);

	/* 7c. Stale foreign IP REQUEST (192.168.45.142) -> DHCPNAK */
	const uint8_t foreign_ip[4] = {192, 168, 45, 142};
	o = 0;
	req.options[o++] = 53; req.options[o++] = 1; req.options[o++] = DHCP_MSG_REQUEST;
	req.options[o++] = 50; req.options[o++] = 4; memcpy(req.options + o, foreign_ip, 4); o += 4;
	req.options[o++] = 255;
	rlen = dhcp_handle_request(&dhcp, &dhcp_cfg, (const uint8_t*)&req,
	                           offsetof(DHCPPacket, options) + o,
	                           resp_raw, sizeof(resp_raw), &send_bcast, ucast_ip);
	assert(rlen >= 300);
	assert(resp->options[0] == 53 && resp->options[1] == 1 && resp->options[2] == DHCP_MSG_NAK);

	/* 7d. Second client DISCOVER -> OFFER 192.168.100.3 (no collision) */
	const uint8_t second_ip[4] = {192, 168, 100, 3};
	memcpy(req.chaddr, client_mac, 6);
	o = 0;
	req.options[o++] = 53; req.options[o++] = 1; req.options[o++] = DHCP_MSG_DISCOVER;
	req.options[o++] = 255;
	rlen = dhcp_handle_request(&dhcp, &dhcp_cfg, (const uint8_t*)&req,
	                           offsetof(DHCPPacket, options) + o,
	                           resp_raw, sizeof(resp_raw), &send_bcast, ucast_ip);
	assert(rlen >= 300);
	assert(resp->options[0] == 53 && resp->options[1] == 1 && resp->options[2] == DHCP_MSG_OFFER);
	assert(memcmp(&resp->yiaddr, second_ip, 4) == 0);

	pthread_mutex_destroy(&dhcp_cfg.fwd_lock);
	pthread_mutex_destroy(&worker_cfg.fwd_lock);
	pthread_mutex_destroy(&cfg.fwd_lock);
	printf("[PASS] 7. Built-in LAN DHCPv4 Server verified (DISCOVER->OFFER .2, REQUEST->ACK+MAC sync, foreign-IP->NAK, 2nd client->.3)\n");

	/* 8. Ctrl+C eventfd wakeup + zero FD leak check */
	int fd_before = count_open_fds();
	int stop_efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	assert(stop_efd >= 0);

	volatile sig_atomic_t running = 1;
	table gc_tbl;
	nat_table_init(&gc_tbl);
	NatGCArg gc_arg = {.nat_table = &gc_tbl, .running = &running, .stop_efd = stop_efd};
	pthread_t gc_tid;
	assert(pthread_create(&gc_tid, NULL, nat_gc_thread, &gc_arg) == 0);

	IDSContext fd_ids;
	const char* fd_log = "/tmp/test_fd_close.log";
	assert(ids_init(&fd_ids, fd_log) == 0);
	assert(count_open_fds() == fd_before + 2); /* stop_efd + fd_ids.log_fp */

	/* Simulate SIGINT handler */
	struct timespec ts0, ts1;
	clock_gettime(CLOCK_MONOTONIC, &ts0);
	running = 0;
	uint64_t one = 1;
	assert(write(stop_efd, &one, sizeof(one)) == sizeof(one));
	pthread_join(gc_tid, NULL);
	clock_gettime(CLOCK_MONOTONIC, &ts1);
	long elapsed_ms = (ts1.tv_sec - ts0.tv_sec) * 1000L + (ts1.tv_nsec - ts0.tv_nsec) / 1000000L;
	assert(elapsed_ms < 500); /* wakes up immediately, NOT waiting 10s GC interval! */

	ids_destroy(&fd_ids);
	destroy(&gc_tbl);
	close(stop_efd);
	remove(fd_log);

	int fd_after = count_open_fds();
	assert(fd_after == fd_before);
	printf("[PASS] 8. Ctrl+C eventfd shutdown (%ld ms) & zero FD leak verified (open FDs before=%d, after=%d)\n",
	       elapsed_ms, fd_before, fd_after);
	printf("=== ALL TESTS PASSED ===\n");
	return 0;
}
