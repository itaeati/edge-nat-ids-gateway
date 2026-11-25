#include "header.h"

/* =========================================================================
 * 체크섬 계산 (RFC 1071)
 * ========================================================================= */

uint16_t packet_checksum(Packet* pip)
{
	if (pip == NULL)
		return 0;

	uint16_t len = (uint16_t)((pip->verihl & 0x0F) << 2);
	if (len < sizeof(Packet))
		return 0;

	const uint8_t* bytes = (const uint8_t*)pip;
	uint32_t dwsum = 0;

	for (size_t i = 0; i < len; i += 2)
	{
		if (i == offsetof(Packet, checksum))
			continue;

		uint16_t word = 0;
		memcpy(&word, bytes + i, sizeof(word));
		dwsum += word;

		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}

	return (uint16_t)(~(dwsum & 0x0000FFFF));
}

uint16_t segment_checksum(Packet* pip, Segment* ptcp)
{
	if (pip == NULL || ptcp == NULL)
		return 0;

	uint16_t ihl = (uint16_t)((pip->verihl & 0x0F) << 2);
	if (ihl < sizeof(Packet))
		return 0;

	uint16_t ip_len = ntohs(pip->length);
	if (ip_len < ihl + sizeof(Segment))
		return 0;

	uint16_t tcp_len = (uint16_t)(ip_len - ihl);

	psuedo psu = {0};
	memcpy(psu.srcip, pip->srcip, 4);
	memcpy(psu.dstip, pip->dstip, 4);
	psu.protocol = pip->protocol;
	psu.length = htons(tcp_len);

	uint32_t dwsum = 0;

	const uint8_t* psu_bytes = (const uint8_t*)&psu;
	for (size_t i = 0; i < sizeof(psuedo); i += 2)
	{
		uint16_t word = 0;
		memcpy(&word, psu_bytes + i, sizeof(word));
		dwsum += word;

		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}

	const uint8_t* tcp_bytes = (const uint8_t*)ptcp;
	for (size_t i = 0; i + 1 < tcp_len; i += 2)
	{
		if (i == offsetof(Segment, checksum))
			continue;

		uint16_t word = 0;
		memcpy(&word, tcp_bytes + i, sizeof(word));
		dwsum += word;

		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}

	if (tcp_len % 2 != 0)
	{
		uint8_t tail[2] = {tcp_bytes[tcp_len - 1], 0};
		uint16_t word = 0;
		memcpy(&word, tail, sizeof(word));
		dwsum += word;

		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}

	return (uint16_t)(~(dwsum & 0x0000FFFF));
}

uint16_t udp_checksum(Packet* pip, UdpHeader* pudp)
{
	if (pip == NULL || pudp == NULL)
		return 0;

	uint16_t ihl = (uint16_t)((pip->verihl & 0x0F) << 2);
	if (ihl < sizeof(Packet))
		return 0;

	uint16_t ip_len = ntohs(pip->length);
	uint16_t udp_len = ntohs(pudp->length);
	if (udp_len < sizeof(UdpHeader) || ip_len < ihl + udp_len)
		return 0;

	psuedo psu = {0};
	memcpy(psu.srcip, pip->srcip, 4);
	memcpy(psu.dstip, pip->dstip, 4);
	psu.protocol = pip->protocol;
	psu.length = pudp->length;

	uint32_t dwsum = 0;

	const uint8_t* psu_bytes = (const uint8_t*)&psu;
	for (size_t i = 0; i < sizeof(psuedo); i += 2)
	{
		uint16_t word = 0;
		memcpy(&word, psu_bytes + i, sizeof(word));
		dwsum += word;

		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}

	const uint8_t* udp_bytes = (const uint8_t*)pudp;
	for (size_t i = 0; i + 1 < udp_len; i += 2)
	{
		if (i == offsetof(UdpHeader, checksum))
			continue;

		uint16_t word = 0;
		memcpy(&word, udp_bytes + i, sizeof(word));
		dwsum += word;

		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}

	if (udp_len % 2 != 0)
	{
		uint8_t tail[2] = {udp_bytes[udp_len - 1], 0};
		uint16_t word = 0;
		memcpy(&word, tail, sizeof(word));
		dwsum += word;

		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}

	uint16_t res = (uint16_t)(~(dwsum & 0x0000FFFF));
	return (res == 0) ? 0xFFFF : res;
}

uint16_t icmp_checksum(const uint8_t* data, size_t len)
{
	if (data == NULL || len < sizeof(IcmpHeader))
		return 0;

	uint32_t dwsum = 0;

	for (size_t i = 0; i + 1 < len; i += 2)
	{
		if (i == offsetof(IcmpHeader, checksum))
			continue;

		uint16_t word = 0;
		memcpy(&word, data + i, sizeof(word));
		dwsum += word;

		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}

	if (len % 2 != 0)
	{
		uint8_t tail[2] = {data[len - 1], 0};
		uint16_t word = 0;
		memcpy(&word, tail, sizeof(word));
		dwsum += word;

		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}

	return (uint16_t)(~(dwsum & 0x0000FFFF));
}

/* =========================================================================
 * NAT 테이블 관리 (pthread_mutex 동기화 지원)
 * ========================================================================= */

static int nat_port_in_use_locked(const table* tbl, uint16_t natport_net)
{
	const node* cur = tbl->head;
	while (cur != NULL)
	{
		if (cur->natport == natport_net)
			return 1;
		cur = cur->next;
	}
	return 0;
}

static uint16_t nat_alloc_port_locked(table* tbl)
{
	uint32_t range = (uint32_t)(NAT_PORT_MAX - NAT_PORT_MIN + 1);
	for (uint32_t tries = 0; tries < range; tries++)
	{
		uint16_t cand = tbl->next_port;
		if (cand < NAT_PORT_MIN || cand > NAT_PORT_MAX)
			cand = NAT_PORT_MIN;

		tbl->next_port = (cand >= NAT_PORT_MAX) ? NAT_PORT_MIN : (uint16_t)(cand + 1);
		uint16_t cand_net = htons(cand);
		if (!nat_port_in_use_locked(tbl, cand_net))
			return cand_net;
	}
	return 0;
}

void nat_table_init(table* tbl)
{
	if (tbl == NULL)
		return;

	tbl->size = 0;
	tbl->head = NULL;
	tbl->prior = 0;
	tbl->next_port = NAT_PORT_MIN;
	pthread_mutex_init(&tbl->lock, NULL);
}

int nat_table_add(table* tbl, const uint8_t* Pack)
{
	if (Pack == NULL || tbl == NULL)
	{
		fprintf(stderr, "input segment's wrong\n");
		return -1;
	}

	const Packet* pip = (const Packet*)Pack;
	uint16_t ihl = (uint16_t)((pip->verihl & 0x0F) << 2);

	if (ihl < sizeof(Packet))
	{
		fprintf(stderr, "invalid IP header length\n");
		return -1;
	}

	if (pip->length != 0 && (size_t)ntohs(pip->length) < (size_t)ihl + sizeof(Segment))
	{
		fprintf(stderr, "invalid packet total length\n");
		return -1;
	}

	const Segment* ptcp = (const Segment*)(Pack + ihl);

	node* obj = calloc(1, sizeof(node));
	if (obj == NULL)
	{
		perror("Node calloc failed");
		return -1;
	}

	pthread_mutex_lock(&tbl->lock);

	uint16_t natport = nat_alloc_port_locked(tbl);
	if (natport == 0)
	{
		pthread_mutex_unlock(&tbl->lock);
		free(obj);
		fprintf(stderr, "NAT port pool exhausted\n");
		return -1;
	}

	memcpy(obj->srcip, pip->srcip, 4);
	memcpy(obj->dstip, pip->dstip, 4);
	obj->srcport = ptcp->srcport;
	obj->dstport = ptcp->dstport;
	obj->natport = natport;
	obj->protocol = pip->protocol;
	obj->seq = ptcp->seq;
	obj->ack = ptcp->ack;
	obj->time = time(NULL);
	obj->flags = (uint8_t)(ntohs(ptcp->flags) & 0x00FF);
	obj->next = NULL;

	if (tbl->head == NULL || tbl->size == 0)
		tbl->head = obj;
	else
	{
		node* temp = tbl->head;
		while (temp->next != NULL)
			temp = temp->next;
		temp->next = obj;
	}

	tbl->size++;
	pthread_mutex_unlock(&tbl->lock);

	return 0;
}

int nat_table_rem(table* tbl, const uint8_t* ip)
{
	if (tbl == NULL || ip == NULL)
	{
		fprintf(stderr, "input segment's wrong\n");
		return -2;
	}

	pthread_mutex_lock(&tbl->lock);

	if (tbl->head == NULL || tbl->size == 0)
	{
		pthread_mutex_unlock(&tbl->lock);
		return 0;
	}

	node* temp = tbl->head;
	node* old = NULL;

	while (temp != NULL)
	{
		if (memcmp(temp->srcip, ip, 4) == 0)
			break;
		old = temp;
		temp = temp->next;
	}

	if (temp == NULL)
	{
		pthread_mutex_unlock(&tbl->lock);
		return -3;
	}

	if (old == NULL)
		tbl->head = temp->next;
	else
		old->next = temp->next;

	free(temp);
	tbl->size--;

	pthread_mutex_unlock(&tbl->lock);
	return 0;
}

int nat_table_expire(table* tbl, time_t now, int timeout_sec)
{
	if (tbl == NULL || timeout_sec <= 0)
		return 0;

	int removed = 0;

	pthread_mutex_lock(&tbl->lock);

	node* cur = tbl->head;
	node* prev = NULL;

	while (cur != NULL)
	{
		if ((now - cur->time) >= timeout_sec)
		{
			node* victim = cur;
			if (prev == NULL)
				tbl->head = cur->next;
			else
				prev->next = cur->next;

			cur = cur->next;
			free(victim);
			tbl->size--;
			removed++;
		}
		else
		{
			prev = cur;
			cur = cur->next;
		}
	}

	pthread_mutex_unlock(&tbl->lock);
	return removed;
}

void* nat_gc_thread(void* arg)
{
	NatGCArg* gc_arg = (NatGCArg*)arg;
	if (gc_arg == NULL || gc_arg->nat_table == NULL || gc_arg->running == NULL)
		return NULL;

	while (*(gc_arg->running))
	{
		if (gc_arg->stop_efd >= 0)
		{
			struct pollfd pfd = {.fd = gc_arg->stop_efd, .events = POLLIN};
			int prc = poll(&pfd, 1, NAT_GC_INTERVAL_SEC * 1000);
			if (prc > 0 || !*(gc_arg->running))
				break;
		}
		else
		{
			for (int sec = 0; sec < NAT_GC_INTERVAL_SEC && *(gc_arg->running); sec++)
				sleep(1);
			if (!*(gc_arg->running))
				break;
		}

		int expired = nat_table_expire(gc_arg->nat_table, time(NULL), NAT_TIMEOUT_SEC);
		if (expired > 0)
			printf("[NAT-GC] Expired %d stale session(s)\n", expired);
	}

	return NULL;
}

void destroy(table* tbl)
{
	if (tbl == NULL)
		return;

	pthread_mutex_lock(&tbl->lock);

	node* temp = tbl->head;
	while (temp != NULL)
	{
		tbl->head = temp->next;
		free(temp);
		temp = tbl->head;
		tbl->size--;
	}

	pthread_mutex_unlock(&tbl->lock);
	pthread_mutex_destroy(&tbl->lock);
	memset(tbl, 0, sizeof(table));
}

/* =========================================================================
 * L3/L4 NAT 변환 (Outbound SNAT / Inbound DNAT + 포트 포워딩)
 * 지원 프로토콜: TCP, UDP, ICMP (Echo Request/Reply)
 * ========================================================================= */

static int is_non_routable_lan_dst(const RouterConfig* cfg, const uint8_t dstip[4])
{
	/* 로컬 라우터(LAN IP) 자신으로 오는 트래픽은 커널이 처리하도록 제외 */
	if (cfg->has_lan_ip && memcmp(dstip, cfg->lan_ip, 4) == 0)
		return 1;
	/* 0.x, 루프백(127.x), 멀티캐스트/예약(224.0.0.0 이상) 제외 */
	if (dstip[0] == 0 || dstip[0] == 127 || dstip[0] >= 224)
		return 1;
	/* 글로벌 브로드캐스트 또는 LAN /24 브로드캐스트 제외 */
	if (dstip[0] == 255 && dstip[1] == 255 && dstip[2] == 255 && dstip[3] == 255)
		return 1;
	if (cfg->has_lan_ip && memcmp(dstip, cfg->lan_ip, 3) == 0 && dstip[3] == 255)
		return 1;
	return 0;
}

int nat_outbound_snat(RouterConfig* cfg, table* tbl, uint8_t* frame_buf, size_t frame_len)
{
	if (cfg == NULL || tbl == NULL || frame_buf == NULL)
		return -1;
	if (frame_len < sizeof(Frame) + sizeof(Packet))
		return -1;

	Frame* eth = (Frame*)frame_buf;
	Packet* pip = (Packet*)(frame_buf + sizeof(Frame));

	uint16_t ihl = (uint16_t)((pip->verihl & 0x0F) << 2);
	uint16_t ip_len = ntohs(pip->length);
	if (ihl < sizeof(Packet) || sizeof(Frame) + ip_len > frame_len)
		return -1;

	/* 포트 포워딩 대상 젯슨 MAC 자동 학습 */
	if (cfg->has_port_fwd)
	{
		pthread_mutex_lock(&cfg->fwd_lock);
		if (memcmp(pip->srcip, cfg->fwd_lan_ip, 4) == 0)
		{
			memcpy(cfg->fwd_lan_mac, eth->srcMac, 6);
			cfg->has_fwd_lan_mac = 1;
		}
		pthread_mutex_unlock(&cfg->fwd_lock);
	}

	if (is_non_routable_lan_dst(cfg, pip->dstip))
		return 1;

	if (pip->ttl <= 1)
		return -1;

	Segment* ptcp = NULL;
	UdpHeader* pudp = NULL;
	IcmpHeader* picmp = NULL;
	uint16_t srcport = 0;
	uint16_t dstport = 0;
	uint8_t tcp_flags = 0;

	if (pip->protocol == IPPROTO_TCP)
	{
		if (ip_len < ihl + sizeof(Segment))
			return -1;
		ptcp = (Segment*)(frame_buf + sizeof(Frame) + ihl);
		srcport = ptcp->srcport;
		dstport = ptcp->dstport;
		tcp_flags = (uint8_t)(ntohs(ptcp->flags) & 0x00FF);
	}
	else if (pip->protocol == IPPROTO_UDP)
	{
		if (ip_len < ihl + sizeof(UdpHeader))
			return -1;
		pudp = (UdpHeader*)(frame_buf + sizeof(Frame) + ihl);
		uint16_t udp_len = ntohs(pudp->length);
		if (udp_len < sizeof(UdpHeader) || ip_len < ihl + udp_len)
			return -1;
		srcport = pudp->srcport;
		dstport = pudp->dstport;
	}
	else if (pip->protocol == IPPROTO_ICMP)
	{
		if (ip_len < ihl + sizeof(IcmpHeader))
			return -1;
		picmp = (IcmpHeader*)(frame_buf + sizeof(Frame) + ihl);
		if (picmp->type != 8) /* Echo Request만 NAT */
			return 1;
		srcport = picmp->id;
		dstport = 0;
	}
	else
	{
		return 1;
	}

	time_t now = time(NULL);
	uint16_t natport = 0;
	uint8_t out_dst_mac[6];
	memcpy(out_dst_mac, cfg->gw_mac, 6);

	pthread_mutex_lock(&tbl->lock);

	node* cur = tbl->head;
	while (cur != NULL)
	{
		if (cur->protocol == pip->protocol &&
			cur->srcport == srcport &&
			cur->dstport == dstport &&
			memcmp(cur->srcip, pip->srcip, 4) == 0 &&
			memcmp(cur->dstip, pip->dstip, 4) == 0)
		{
			memcpy(cur->srcMac, eth->srcMac, 6);
			if (ptcp != NULL)
			{
				cur->seq = ptcp->seq;
				cur->ack = ptcp->ack;
				cur->flags = tcp_flags;
			}
			cur->time = now;
			natport = cur->natport;
			if (cur->has_peer_mac)
				memcpy(out_dst_mac, cur->peer_mac, 6);
			break;
		}
		cur = cur->next;
	}

	if (cur == NULL)
	{
		node* obj = calloc(1, sizeof(node));
		if (obj == NULL)
		{
			pthread_mutex_unlock(&tbl->lock);
			return -1;
		}

		natport = nat_alloc_port_locked(tbl);
		if (natport == 0)
		{
			pthread_mutex_unlock(&tbl->lock);
			free(obj);
			return -1;
		}

		memcpy(obj->srcip, pip->srcip, 4);
		memcpy(obj->dstip, pip->dstip, 4);
		memcpy(obj->srcMac, eth->srcMac, 6);
		obj->srcport = srcport;
		obj->dstport = dstport;
		obj->natport = natport;
		obj->protocol = pip->protocol;
		if (ptcp != NULL)
		{
			obj->seq = ptcp->seq;
			obj->ack = ptcp->ack;
			obj->flags = tcp_flags;
		}
		obj->time = now;
		obj->next = tbl->head;

		tbl->head = obj;
		tbl->size++;
	}

	pthread_mutex_unlock(&tbl->lock);

	if (!cfg->has_wan_l3)
		return 1;

	/* L3/L4 SNAT + TTL 감소 + 체크섬 재계산 */
	memcpy(pip->srcip, cfg->wan_ip, 4);
	pip->ttl--;
	pip->checksum = packet_checksum(pip);

	if (ptcp != NULL)
	{
		ptcp->srcport = natport;
		ptcp->checksum = segment_checksum(pip, ptcp);
	}
	else if (pudp != NULL)
	{
		pudp->srcport = natport;
		pudp->checksum = udp_checksum(pip, pudp);
	}
	else if (picmp != NULL)
	{
		picmp->id = natport;
		picmp->checksum = icmp_checksum((const uint8_t*)picmp, (size_t)(ip_len - ihl));
	}

	memcpy(eth->srcMac, cfg->wan_mac, 6);
	memcpy(eth->dstMac, out_dst_mac, 6);

	return 0;
}

int nat_inbound_dnat(RouterConfig* cfg, table* tbl, uint8_t* frame_buf, size_t frame_len)
{
	if (cfg == NULL || tbl == NULL || frame_buf == NULL)
		return -1;
	if (!cfg->has_wan_l3)
		return 1;
	if (frame_len < sizeof(Frame) + sizeof(Packet))
		return -1;

	Frame* eth = (Frame*)frame_buf;
	Packet* pip = (Packet*)(frame_buf + sizeof(Frame));

	uint16_t ihl = (uint16_t)((pip->verihl & 0x0F) << 2);
	uint16_t ip_len = ntohs(pip->length);
	if (ihl < sizeof(Packet) || sizeof(Frame) + ip_len > frame_len)
		return -1;
	if (memcmp(pip->dstip, cfg->wan_ip, 4) != 0)
		return 1;
	if (pip->ttl <= 1)
		return -1;

	Segment* ptcp = NULL;
	UdpHeader* pudp = NULL;
	IcmpHeader* picmp = NULL;
	uint16_t in_dstport = 0;
	uint16_t in_srcport = 0;
	uint8_t tcp_flags = 0;

	if (pip->protocol == IPPROTO_TCP)
	{
		if (ip_len < ihl + sizeof(Segment))
			return -1;
		ptcp = (Segment*)(frame_buf + sizeof(Frame) + ihl);
		in_dstport = ptcp->dstport;
		in_srcport = ptcp->srcport;
		tcp_flags = (uint8_t)(ntohs(ptcp->flags) & 0x00FF);
	}
	else if (pip->protocol == IPPROTO_UDP)
	{
		if (ip_len < ihl + sizeof(UdpHeader))
			return -1;
		pudp = (UdpHeader*)(frame_buf + sizeof(Frame) + ihl);
		uint16_t udp_len = ntohs(pudp->length);
		if (udp_len < sizeof(UdpHeader) || ip_len < ihl + udp_len)
			return -1;
		in_dstport = pudp->dstport;
		in_srcport = pudp->srcport;
	}
	else if (pip->protocol == IPPROTO_ICMP)
	{
		if (ip_len < ihl + sizeof(IcmpHeader))
			return -1;
		picmp = (IcmpHeader*)(frame_buf + sizeof(Frame) + ihl);
		if (picmp->type != 0) /* Echo Reply만 DNAT */
			return 1;
		in_dstport = picmp->id;
		in_srcport = 0;
	}
	else
	{
		return 1;
	}

	uint8_t fwd_lan_ip_local[4] = {0};
	uint8_t fwd_lan_mac_local[6] = {0};
	int has_fwd_mac_local = 0;
	int is_fwd_match = (cfg->has_port_fwd &&
	                    pip->protocol == IPPROTO_TCP &&
	                    in_dstport == cfg->fwd_wan_port);
	if (is_fwd_match)
	{
		pthread_mutex_lock(&cfg->fwd_lock);
		memcpy(fwd_lan_ip_local, cfg->fwd_lan_ip, 4);
		has_fwd_mac_local = cfg->has_fwd_lan_mac;
		if (has_fwd_mac_local)
			memcpy(fwd_lan_mac_local, cfg->fwd_lan_mac, 6);
		pthread_mutex_unlock(&cfg->fwd_lock);

		if (!has_fwd_mac_local &&
			get_arp_mac(cfg->lan_if, fwd_lan_ip_local, fwd_lan_mac_local) == 0)
		{
			has_fwd_mac_local = 1;
			pthread_mutex_lock(&cfg->fwd_lock);
			memcpy(cfg->fwd_lan_mac, fwd_lan_mac_local, 6);
			cfg->has_fwd_lan_mac = 1;
			pthread_mutex_unlock(&cfg->fwd_lock);
		}
	}

	uint8_t orig_srcip[4] = {0};
	uint8_t orig_srcMac[6] = {0};
	uint16_t orig_srcport = 0;
	int found = 0;
	time_t now = time(NULL);

	pthread_mutex_lock(&tbl->lock);

	node* cur = tbl->head;
	while (cur != NULL)
	{
		if (cur->protocol == pip->protocol &&
			cur->natport == in_dstport &&
			cur->dstport == in_srcport &&
			memcmp(cur->dstip, pip->srcip, 4) == 0)
		{
			memcpy(orig_srcip, cur->srcip, 4);
			memcpy(orig_srcMac, cur->srcMac, 6);
			orig_srcport = cur->srcport;
			if (ptcp != NULL)
				cur->flags = tcp_flags;
			memcpy(cur->peer_mac, eth->srcMac, 6);
			cur->has_peer_mac = 1;
			cur->time = now;
			found = 1;
			break;
		}
		cur = cur->next;
	}

	if (!found && is_fwd_match && has_fwd_mac_local)
	{
		node* obj = calloc(1, sizeof(node));
		if (obj != NULL)
		{
			memcpy(obj->srcip, fwd_lan_ip_local, 4);
			memcpy(obj->dstip, pip->srcip, 4);
			memcpy(obj->srcMac, fwd_lan_mac_local, 6);
			memcpy(obj->peer_mac, eth->srcMac, 6);
			obj->has_peer_mac = 1;
			obj->srcport = cfg->fwd_lan_port;
			obj->dstport = in_srcport;
			obj->natport = cfg->fwd_wan_port;
			obj->protocol = IPPROTO_TCP;
			obj->flags = tcp_flags;
			obj->seq = ptcp->seq;
			obj->ack = ptcp->ack;
			obj->time = now;
			obj->next = tbl->head;

			tbl->head = obj;
			tbl->size++;

			memcpy(orig_srcip, fwd_lan_ip_local, 4);
			memcpy(orig_srcMac, fwd_lan_mac_local, 6);
			orig_srcport = cfg->fwd_lan_port;
			found = 1;
		}
	}

	pthread_mutex_unlock(&tbl->lock);

	if (!found)
		return 1;

	/* L3/L4 DNAT 복원 + TTL 감소 + 체크섬 재계산 */
	memcpy(pip->dstip, orig_srcip, 4);
	pip->ttl--;
	pip->checksum = packet_checksum(pip);

	if (ptcp != NULL)
	{
		ptcp->dstport = orig_srcport;
		ptcp->checksum = segment_checksum(pip, ptcp);
	}
	else if (pudp != NULL)
	{
		pudp->dstport = orig_srcport;
		pudp->checksum = udp_checksum(pip, pudp);
	}
	else if (picmp != NULL)
	{
		picmp->id = orig_srcport;
		picmp->checksum = icmp_checksum((const uint8_t*)picmp, (size_t)(ip_len - ihl));
	}

	memcpy(eth->srcMac, cfg->lan_mac, 6);
	memcpy(eth->dstMac, orig_srcMac, 6);

	return 0;
}

/* =========================================================================
 * IDS 이상 트래픽 탐지 (비정상 TCP 플래그, LAND, SYN Flood, 포트 스캔)
 * ========================================================================= */

int ids_init(IDSContext* ctx, const char* log_path)
{
	if (ctx == NULL)
		return -1;
	memset(ctx, 0, sizeof(*ctx));
	pthread_mutex_init(&ctx->lock, NULL);

	if (log_path != NULL && log_path[0] != '\0')
	{
		ctx->log_fp = fopen(log_path, "ae");
		if (ctx->log_fp == NULL)
			return -1;
	}
	return 0;
}

void ids_destroy(IDSContext* ctx)
{
	if (ctx == NULL)
		return;

	pthread_mutex_lock(&ctx->lock);
	if (ctx->log_fp != NULL)
	{
		fflush(ctx->log_fp);
		fclose(ctx->log_fp);
		ctx->log_fp = NULL;
	}
	pthread_mutex_unlock(&ctx->lock);

	pthread_mutex_destroy(&ctx->lock);
	memset(ctx, 0, sizeof(*ctx));
}

static void format_tcp_flags(uint8_t flags6, char* out, size_t out_sz)
{
	if (flags6 == 0)
	{
		snprintf(out, out_sz, "NONE");
		return;
	}

	out[0] = '\0';
	const struct { uint8_t bit; const char* name; } map[] = {
		{TCP_FLAG_SYN, "SYN"},
		{TCP_FLAG_ACK, "ACK"},
		{TCP_FLAG_FIN, "FIN"},
		{TCP_FLAG_RST, "RST"},
		{TCP_FLAG_PSH, "PSH"},
		{TCP_FLAG_URG, "URG"},
	};

	size_t used = 0;
	for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++)
	{
		if (flags6 & map[i].bit)
		{
			int n = snprintf(out + used, out_sz - used, "%s%s",
							 (used > 0) ? "," : "", map[i].name);
			if (n > 0 && (size_t)n < out_sz - used)
				used += (size_t)n;
		}
	}
}

void ids_log_alert(IDSContext* ctx, const char* direction, const char* reason,
                   const Frame* eth, const Packet* pip, const Segment* ptcp, time_t now)
{
	if (pip == NULL || ptcp == NULL)
		return;

	struct tm tm_buf;
	char time_str[32] = "0000-00-00 00:00:00";
	if (localtime_r(&now, &tm_buf) != NULL)
		strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

	uint8_t flags6 = (uint8_t)(ntohs(ptcp->flags) & 0x3F);
	char flag_str[32];
	format_tcp_flags(flags6, flag_str, sizeof(flag_str));

	char mac_part[80] = "";
	if (eth != NULL)
	{
		snprintf(mac_part, sizeof(mac_part),
				 " src_mac=%02X:%02X:%02X:%02X:%02X:%02X dst_mac=%02X:%02X:%02X:%02X:%02X:%02X",
				 eth->srcMac[0], eth->srcMac[1], eth->srcMac[2],
				 eth->srcMac[3], eth->srcMac[4], eth->srcMac[5],
				 eth->dstMac[0], eth->dstMac[1], eth->dstMac[2],
				 eth->dstMac[3], eth->dstMac[4], eth->dstMac[5]);
	}

	char line[512];
	snprintf(line, sizeof(line),
			 "[%s] [IDS DROP] dir=%s reason=\"%s\" src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u"
			 " flags=0x%02X(%s) len=%u%s\n",
			 time_str,
			 direction ? direction : "UNKNOWN",
			 reason ? reason : "Anomaly",
			 pip->srcip[0], pip->srcip[1], pip->srcip[2], pip->srcip[3], ntohs(ptcp->srcport),
			 pip->dstip[0], pip->dstip[1], pip->dstip[2], pip->dstip[3], ntohs(ptcp->dstport),
			 flags6, flag_str, (unsigned)ntohs(pip->length), mac_part);

	fputs(line, stderr);

	if (ctx != NULL)
	{
		pthread_mutex_lock(&ctx->lock);
		if (ctx->log_fp != NULL)
		{
			fputs(line, ctx->log_fp);
			fflush(ctx->log_fp);
		}
		pthread_mutex_unlock(&ctx->lock);
	}
}

static IDSHostEntry* ids_get_or_alloc_host_locked(IDSContext* ctx, const uint8_t ip[4], time_t now)
{
	int free_idx = -1;
	int oldest_idx = 0;
	time_t oldest_time = ctx->hosts[0].window_start;

	for (int i = 0; i < IDS_TRACK_SLOTS; i++)
	{
		if (ctx->hosts[i].in_use)
		{
			if (memcmp(ctx->hosts[i].srcip, ip, 4) == 0)
				return &ctx->hosts[i];
			if (ctx->hosts[i].window_start < oldest_time)
			{
				oldest_time = ctx->hosts[i].window_start;
				oldest_idx = i;
			}
		}
		else if (free_idx < 0)
		{
			free_idx = i;
		}
	}

	int slot = (free_idx >= 0) ? free_idx : oldest_idx;
	memset(&ctx->hosts[slot], 0, sizeof(ctx->hosts[slot]));
	ctx->hosts[slot].in_use = 1;
	memcpy(ctx->hosts[slot].srcip, ip, 4);
	ctx->hosts[slot].window_start = now;
	return &ctx->hosts[slot];
}

IDSResult ids_inspect_tcp(IDSContext* ctx, const Packet* pip, const Segment* ptcp,
                          size_t ip_avail, time_t now, const char** reason_out)
{
	if (pip == NULL || ptcp == NULL)
	{
		if (reason_out) *reason_out = "NULL header";
		return IDS_ALERT_DROP;
	}

	uint16_t ihl = (uint16_t)((pip->verihl & 0x0F) << 2);
	uint16_t ip_len = ntohs(pip->length);
	uint16_t raw_flags = ntohs(ptcp->flags);
	uint16_t tcp_hlen = (uint16_t)(((raw_flags >> 12) & 0x0F) << 2);
	uint8_t flags6 = (uint8_t)(raw_flags & 0x3F);

	/* 1. 비정상 헤더 길이 검사 */
	if (ihl < sizeof(Packet) || tcp_hlen < sizeof(Segment) ||
		ip_len < ihl + tcp_hlen || ip_len > ip_avail)
	{
		if (reason_out) *reason_out = "Malformed IP/TCP header length";
		return IDS_ALERT_DROP;
	}

	/* 2. LAND 공격 (출발지 IP == 목적지 IP) */
	if (memcmp(pip->srcip, pip->dstip, 4) == 0)
	{
		if (reason_out) *reason_out = "LAND attack (srcIP == dstIP)";
		return IDS_ALERT_DROP;
	}

	/* 3. 비정상 TCP 플래그 조합 (NULL / Xmas / SYN+FIN / SYN+RST / FIN+RST) */
	if (flags6 == 0)
	{
		if (reason_out) *reason_out = "TCP NULL scan (flags=0)";
		return IDS_ALERT_DROP;
	}
	if ((flags6 & (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG)) ==
		(TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG))
	{
		if (reason_out) *reason_out = "TCP Xmas scan (FIN+PSH+URG)";
		return IDS_ALERT_DROP;
	}
	if ((flags6 & (TCP_FLAG_SYN | TCP_FLAG_FIN)) == (TCP_FLAG_SYN | TCP_FLAG_FIN))
	{
		if (reason_out) *reason_out = "Invalid TCP flags (SYN+FIN)";
		return IDS_ALERT_DROP;
	}
	if ((flags6 & (TCP_FLAG_SYN | TCP_FLAG_RST)) == (TCP_FLAG_SYN | TCP_FLAG_RST))
	{
		if (reason_out) *reason_out = "Invalid TCP flags (SYN+RST)";
		return IDS_ALERT_DROP;
	}
	if ((flags6 & (TCP_FLAG_FIN | TCP_FLAG_RST)) == (TCP_FLAG_FIN | TCP_FLAG_RST))
	{
		if (reason_out) *reason_out = "Invalid TCP flags (FIN+RST)";
		return IDS_ALERT_DROP;
	}

	/* 4. 상태 기반 탐지: SYN Flood & 포트 스캔 */
	if (ctx != NULL && (flags6 & TCP_FLAG_SYN) && !(flags6 & TCP_FLAG_ACK))
	{
		pthread_mutex_lock(&ctx->lock);

		IDSHostEntry* host = ids_get_or_alloc_host_locked(ctx, pip->srcip, now);
		if ((now - host->window_start) >= IDS_WINDOW_SEC)
		{
			host->window_start = now;
			host->syn_count = 0;
			host->port_count = 0;
		}

		host->syn_count++;
		if (host->syn_count > IDS_SYN_FLOOD_LIMIT)
		{
			pthread_mutex_unlock(&ctx->lock);
			if (reason_out) *reason_out = "TCP SYN Flood detected";
			return IDS_ALERT_DROP;
		}

		uint16_t dport = ntohs(ptcp->dstport);
		int seen = 0;
		for (uint32_t i = 0; i < host->port_count; i++)
		{
			if (host->recent_ports[i] == dport)
			{
				seen = 1;
				break;
			}
		}

		if (!seen)
		{
			if (host->port_count < IDS_PORT_SCAN_LIMIT)
				host->recent_ports[host->port_count++] = dport;

			if (host->port_count >= IDS_PORT_SCAN_LIMIT)
			{
				pthread_mutex_unlock(&ctx->lock);
				if (reason_out) *reason_out = "TCP Port Scan detected";
				return IDS_ALERT_DROP;
			}
		}

		pthread_mutex_unlock(&ctx->lock);
	}

	if (reason_out) *reason_out = NULL;
	return IDS_ALLOW;
}

/* =========================================================================
 * 전용 IDS + NAT 포워딩 워커 스레드 & 패킷 링버퍼 큐
 * ========================================================================= */

void pkt_queue_init(PacketQueue* q)
{
	if (q == NULL)
		return;
	memset(q, 0, sizeof(*q));
	pthread_mutex_init(&q->lock, NULL);
	pthread_cond_init(&q->not_empty, NULL);
}

int pkt_queue_push(PacketQueue* q, const uint8_t* data, size_t len, int is_from_lan, time_t rx_time)
{
	if (q == NULL || data == NULL || len == 0 || len > PKT_MAX_FRAME)
		return -1;

	pthread_mutex_lock(&q->lock);
	if (q->stopped || q->count >= PKT_QUEUE_CAP)
	{
		pthread_mutex_unlock(&q->lock);
		return -1;
	}

	PacketItem* slot = &q->items[q->tail];
	memcpy(slot->data, data, len);
	slot->len = len;
	slot->is_from_lan = is_from_lan;
	slot->rx_time = rx_time;

	q->tail = (q->tail + 1) % PKT_QUEUE_CAP;
	q->count++;

	pthread_cond_signal(&q->not_empty);
	pthread_mutex_unlock(&q->lock);
	return 0;
}

int pkt_queue_pop(PacketQueue* q, PacketItem* out)
{
	if (q == NULL || out == NULL)
		return -1;

	pthread_mutex_lock(&q->lock);
	while (q->count == 0 && !q->stopped)
		pthread_cond_wait(&q->not_empty, &q->lock);

	if (q->count == 0 && q->stopped)
	{
		pthread_mutex_unlock(&q->lock);
		return -1;
	}

	*out = q->items[q->head];
	q->head = (q->head + 1) % PKT_QUEUE_CAP;
	q->count--;

	pthread_mutex_unlock(&q->lock);
	return 0;
}

void pkt_queue_stop(PacketQueue* q)
{
	if (q == NULL)
		return;

	pthread_mutex_lock(&q->lock);
	q->stopped = 1;
	pthread_cond_broadcast(&q->not_empty);
	pthread_mutex_unlock(&q->lock);
}

void pkt_queue_destroy(PacketQueue* q)
{
	if (q == NULL)
		return;
	pthread_cond_destroy(&q->not_empty);
	pthread_mutex_destroy(&q->lock);
	memset(q, 0, sizeof(*q));
}

void* ids_worker_thread(void* arg)
{
	WorkerArg* w = (WorkerArg*)arg;
	if (w == NULL || w->cfg == NULL || w->nat_table == NULL || w->queue == NULL)
		return NULL;

	PacketItem item;
	while (pkt_queue_pop(w->queue, &item) == 0)
	{
		if (item.len < sizeof(Frame) + sizeof(Packet))
			continue;

		const Frame* pether = (const Frame*)item.data;
		Packet* pip = (Packet*)(item.data + sizeof(Frame));
		uint16_t ihl = (uint16_t)((pip->verihl & 0x0F) << 2);
		size_t ip_avail = item.len - sizeof(Frame);

		if (ihl < sizeof(Packet))
			continue;

		/* 1) 전용 IDS 스레드에서 TCP 이상 트래픽 검사 및 차단(DROP) */
		if (pip->protocol == IPPROTO_TCP)
		{
			if (ip_avail < (size_t)ihl + sizeof(Segment))
				continue;

			Segment* ptcp = (Segment*)(item.data + sizeof(Frame) + ihl);
			const char* ids_reason = NULL;
			if (ids_inspect_tcp(w->ids_ctx, pip, ptcp, ip_avail, item.rx_time, &ids_reason) == IDS_ALERT_DROP)
			{
				ids_log_alert(w->ids_ctx, item.is_from_lan ? "LAN->WAN" : "WAN->LAN",
							  ids_reason, pether, pip, ptcp, item.rx_time);
				continue;
			}
		}
		else if (pip->protocol == IPPROTO_UDP)
		{
			if (ip_avail < (size_t)ihl + sizeof(UdpHeader))
				continue;
		}
		else if (pip->protocol == IPPROTO_ICMP)
		{
			if (ip_avail < (size_t)ihl + sizeof(IcmpHeader))
				continue;
		}
		else
		{
			continue;
		}

		/* 2) IDS 통과 패킷만 방향별 NAT / 포트 포워딩 변환 후 송신 */
		if (item.is_from_lan)
		{
			int rc = nat_outbound_snat(w->cfg, w->nat_table, item.data, item.len);
			if (rc == 0)
			{
				if (sendto(w->hsock, item.data, item.len, 0,
						   (const struct sockaddr*)&w->wan_dst, sizeof(w->wan_dst)) < 0)
				{
					if (errno != EINTR && errno != EAGAIN)
						perror("sendto(WAN) failed");
				}
			}
		}
		else
		{
			int rc = nat_inbound_dnat(w->cfg, w->nat_table, item.data, item.len);
			if (rc == 0)
			{
				if (sendto(w->hsock, item.data, item.len, 0,
						   (const struct sockaddr*)&w->lan_dst, sizeof(w->lan_dst)) < 0)
				{
					if (errno != EINTR && errno != EAGAIN)
						perror("sendto(LAN) failed");
				}
			}
		}
	}

	return NULL;
}

/* =========================================================================
 * 내장 LAN DHCPv4 서버 스레드 (RFC 2131, LAN 인터페이스 전용)
 * ========================================================================= */

void dhcp_state_init(DHCPServerState* st, const uint8_t server_ip[4])
{
	if (st == NULL || server_ip == NULL)
		return;

	memset(st, 0, sizeof(*st));
	memcpy(st->server_ip, server_ip, 4);
	st->dns1[0] = 8; st->dns1[1] = 8; st->dns1[2] = 8; st->dns1[3] = 8;
	st->dns2[0] = 1; st->dns2[1] = 1; st->dns2[2] = 1; st->dns2[3] = 1;

	for (int i = 0; i < DHCP_POOL_SIZE; i++)
	{
		st->leases[i].in_use = 0;
		st->leases[i].ip[0] = server_ip[0];
		st->leases[i].ip[1] = server_ip[1];
		st->leases[i].ip[2] = server_ip[2];
		st->leases[i].ip[3] = (uint8_t)(DHCP_POOL_START + i);
		st->leases[i].expire_at = 0;
	}
}

static int dhcp_opt_append(uint8_t* opts, size_t cap, size_t* pos,
                           uint8_t code, uint8_t len, const void* val)
{
	if (*pos + 2 + len + 1 > cap)
		return -1;
	opts[(*pos)++] = code;
	opts[(*pos)++] = len;
	if (len > 0 && val != NULL)
	{
		memcpy(opts + *pos, val, len);
		*pos += len;
	}
	return 0;
}

static DHCPLease* dhcp_find_or_alloc_lease(DHCPServerState* st, const uint8_t mac[6],
                                           int has_req_ip, const uint8_t req_ip[4],
                                           time_t now)
{
	/* 1) 기존 MAC 리스 재사용 */
	for (int i = 0; i < DHCP_POOL_SIZE; i++)
	{
		if (st->leases[i].in_use && memcmp(st->leases[i].mac, mac, 6) == 0)
			return &st->leases[i];
	}

	/* 2) 클라이언트가 요청한 IP가 풀 안에 있고 비어있으면 우선 할당 */
	if (has_req_ip &&
		memcmp(req_ip, st->server_ip, 3) == 0 &&
		req_ip[3] >= DHCP_POOL_START && req_ip[3] <= DHCP_POOL_END)
	{
		int idx = (int)(req_ip[3] - DHCP_POOL_START);
		if (!st->leases[idx].in_use || st->leases[idx].expire_at <= now)
			return &st->leases[idx];
	}

	/* 3) 첫 번째 비어있거나 만료된 슬롯 할당 (첫 기기는 항상 .2) */
	for (int i = 0; i < DHCP_POOL_SIZE; i++)
	{
		if (!st->leases[i].in_use || st->leases[i].expire_at <= now)
			return &st->leases[i];
	}

	return NULL;
}

ssize_t dhcp_handle_request(DHCPServerState* st, RouterConfig* cfg,
                            const uint8_t* req_buf, size_t req_len,
                            uint8_t* resp_buf, size_t resp_cap,
                            int* send_broadcast_out, uint8_t unicast_ip_out[4])
{
	const size_t fixed_hdr_len = offsetof(DHCPPacket, options);
	if (st == NULL || req_buf == NULL || resp_buf == NULL ||
		req_len < fixed_hdr_len || resp_cap < sizeof(DHCPPacket))
		return -1;

	const DHCPPacket* req = (const DHCPPacket*)req_buf;
	if (req->op != 1 || req->htype != 1 || req->hlen != 6)
		return 0;
	if (ntohl(req->magic) != DHCP_MAGIC_COOKIE)
		return 0;

	uint8_t msg_type = 0;
	int has_req_ip = 0;
	uint8_t req_ip[4] = {0};
	int has_srv_id = 0;
	uint8_t srv_id[4] = {0};

	size_t off = fixed_hdr_len;
	while (off < req_len)
	{
		uint8_t code = req_buf[off++];
		if (code == 0)
			continue; /* PAD */
		if (code == 255)
			break;    /* END */
		if (off >= req_len)
			break;
		uint8_t olen = req_buf[off++];
		if (off + olen > req_len)
			break;

		if (code == 53 && olen == 1)
			msg_type = req_buf[off];
		else if (code == 50 && olen == 4)
		{
			memcpy(req_ip, req_buf + off, 4);
			has_req_ip = 1;
		}
		else if (code == 54 && olen == 4)
		{
			memcpy(srv_id, req_buf + off, 4);
			has_srv_id = 1;
		}
		off += olen;
	}

	if (msg_type == 0)
		return 0;

	/* 다른 DHCP 서버를 지목한 REQUEST는 무시 */
	if (has_srv_id && memcmp(srv_id, st->server_ip, 4) != 0)
		return 0;

	const uint8_t* mac = req->chaddr;
	time_t now = time(NULL);

	if (msg_type == DHCP_MSG_RELEASE)
	{
		for (int i = 0; i < DHCP_POOL_SIZE; i++)
		{
			if (st->leases[i].in_use && memcmp(st->leases[i].mac, mac, 6) == 0)
			{
				st->leases[i].in_use = 0;
				st->leases[i].expire_at = 0;
				printf("[DHCP] RELEASE %u.%u.%u.%u from %02X:%02X:%02X:%02X:%02X:%02X\n",
					   st->leases[i].ip[0], st->leases[i].ip[1],
					   st->leases[i].ip[2], st->leases[i].ip[3],
					   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
				fflush(stdout);
				break;
			}
		}
		return 0;
	}

	if (msg_type == DHCP_MSG_DECLINE)
		return 0;

	memset(resp_buf, 0, sizeof(DHCPPacket));
	DHCPPacket* resp = (DHCPPacket*)resp_buf;
	resp->op = 2; /* BOOTREPLY */
	resp->htype = 1;
	resp->hlen = 6;
	resp->xid = req->xid;
	resp->flags = req->flags;
	resp->giaddr = req->giaddr;
	memcpy(resp->chaddr, req->chaddr, 16);
	resp->magic = htonl(DHCP_MAGIC_COOKIE);

	size_t opt_pos = 0;
	const size_t opt_cap = sizeof(resp->options);
	uint8_t subnet_mask[4] = {255, 255, 255, 0};
	uint8_t bcast_ip[4] = {st->server_ip[0], st->server_ip[1], st->server_ip[2], 255};
	uint8_t dns_pair[8];
	memcpy(dns_pair, st->dns1, 4);
	memcpy(dns_pair + 4, st->dns2, 4);
	uint32_t lease_net = htonl(DHCP_LEASE_SEC);
	uint32_t t1_net = htonl(DHCP_LEASE_SEC / 2);
	uint32_t t2_net = htonl((DHCP_LEASE_SEC * 7) / 8);

	if (msg_type == DHCP_MSG_DISCOVER)
	{
		DHCPLease* lease = dhcp_find_or_alloc_lease(st, mac, has_req_ip, req_ip, now);
		if (lease == NULL)
			return 0;

		/* 임시 예약(60초)으로 동시 요청 충돌 방지 */
		memcpy(lease->mac, mac, 6);
		lease->in_use = 1;
		lease->expire_at = now + 60;

		memcpy(&resp->yiaddr, lease->ip, 4);
		memcpy(&resp->siaddr, st->server_ip, 4);

		uint8_t rtype = DHCP_MSG_OFFER;
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 53, 1, &rtype);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 54, 4, st->server_ip);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 51, 4, &lease_net);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 58, 4, &t1_net);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 59, 4, &t2_net);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 1, 4, subnet_mask);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 3, 4, st->server_ip);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 6, 8, dns_pair);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 28, 4, bcast_ip);
		resp->options[opt_pos++] = 255;

		if (send_broadcast_out)
			*send_broadcast_out = 1;

		printf("[DHCP] OFFER %u.%u.%u.%u -> %02X:%02X:%02X:%02X:%02X:%02X\n",
			   lease->ip[0], lease->ip[1], lease->ip[2], lease->ip[3],
			   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		fflush(stdout);
	}
	else if (msg_type == DHCP_MSG_REQUEST)
	{
		uint8_t cand_ip[4] = {0};
		int has_cand = 0;
		if (has_req_ip)
		{
			memcpy(cand_ip, req_ip, 4);
			has_cand = 1;
		}
		else if (req->ciaddr != 0)
		{
			memcpy(cand_ip, &req->ciaddr, 4);
			has_cand = 1;
		}

		DHCPLease* lease = NULL;
		int valid = 0;

		if (has_cand)
		{
			if (memcmp(cand_ip, st->server_ip, 3) == 0 &&
				cand_ip[3] >= DHCP_POOL_START && cand_ip[3] <= DHCP_POOL_END)
			{
				int idx = (int)(cand_ip[3] - DHCP_POOL_START);
				DHCPLease* slot = &st->leases[idx];
				if (!slot->in_use || slot->expire_at <= now ||
					memcmp(slot->mac, mac, 6) == 0)
				{
					lease = slot;
					valid = 1;
				}
			}
		}
		else
		{
			lease = dhcp_find_or_alloc_lease(st, mac, 0, NULL, now);
			valid = (lease != NULL);
		}

		if (!valid || lease == NULL)
		{
			/* 이전 공유기 대역 IP(예: 192.168.45.x) 갱신 시도 시 NAK로 즉시 DISCOVER 유도 */
			uint8_t rtype = DHCP_MSG_NAK;
			dhcp_opt_append(resp->options, opt_cap, &opt_pos, 53, 1, &rtype);
			dhcp_opt_append(resp->options, opt_cap, &opt_pos, 54, 4, st->server_ip);
			resp->options[opt_pos++] = 255;

			if (send_broadcast_out)
				*send_broadcast_out = 1;

			printf("[DHCP] NAK requested %u.%u.%u.%u for %02X:%02X:%02X:%02X:%02X:%02X\n",
				   cand_ip[0], cand_ip[1], cand_ip[2], cand_ip[3],
				   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			fflush(stdout);
		}
		else
		{
			/* 동일 MAC의 다른 구 슬롯이 있으면 해제 */
			for (int i = 0; i < DHCP_POOL_SIZE; i++)
			{
				if (&st->leases[i] != lease && st->leases[i].in_use &&
					memcmp(st->leases[i].mac, mac, 6) == 0)
				{
					st->leases[i].in_use = 0;
					st->leases[i].expire_at = 0;
				}
			}

			memcpy(lease->mac, mac, 6);
			lease->in_use = 1;
			lease->expire_at = now + DHCP_LEASE_SEC;

			/* 포트 포워딩 대상 IP와 일치하면 MAC 자동 동기화 */
			if (cfg != NULL && cfg->has_port_fwd)
			{
				pthread_mutex_lock(&cfg->fwd_lock);
				if (memcmp(lease->ip, cfg->fwd_lan_ip, 4) == 0)
				{
					memcpy(cfg->fwd_lan_mac, mac, 6);
					cfg->has_fwd_lan_mac = 1;
				}
				pthread_mutex_unlock(&cfg->fwd_lock);
			}

			memcpy(&resp->yiaddr, lease->ip, 4);
			memcpy(&resp->siaddr, st->server_ip, 4);
			resp->ciaddr = req->ciaddr;

			uint8_t rtype = DHCP_MSG_ACK;
			dhcp_opt_append(resp->options, opt_cap, &opt_pos, 53, 1, &rtype);
			dhcp_opt_append(resp->options, opt_cap, &opt_pos, 54, 4, st->server_ip);
			dhcp_opt_append(resp->options, opt_cap, &opt_pos, 51, 4, &lease_net);
			dhcp_opt_append(resp->options, opt_cap, &opt_pos, 58, 4, &t1_net);
			dhcp_opt_append(resp->options, opt_cap, &opt_pos, 59, 4, &t2_net);
			dhcp_opt_append(resp->options, opt_cap, &opt_pos, 1, 4, subnet_mask);
			dhcp_opt_append(resp->options, opt_cap, &opt_pos, 3, 4, st->server_ip);
			dhcp_opt_append(resp->options, opt_cap, &opt_pos, 6, 8, dns_pair);
			dhcp_opt_append(resp->options, opt_cap, &opt_pos, 28, 4, bcast_ip);
			resp->options[opt_pos++] = 255;

			if (req->ciaddr != 0 && (ntohs(req->flags) & 0x8000) == 0)
			{
				if (send_broadcast_out)
					*send_broadcast_out = 0;
				if (unicast_ip_out)
					memcpy(unicast_ip_out, &req->ciaddr, 4);
			}
			else if (send_broadcast_out)
			{
				*send_broadcast_out = 1;
			}

			printf("[DHCP] ACK %u.%u.%u.%u -> %02X:%02X:%02X:%02X:%02X:%02X (lease=%ds, gw=%u.%u.%u.%u, dns=%u.%u.%u.%u/%u.%u.%u.%u)\n",
				   lease->ip[0], lease->ip[1], lease->ip[2], lease->ip[3],
				   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
				   DHCP_LEASE_SEC,
				   st->server_ip[0], st->server_ip[1], st->server_ip[2], st->server_ip[3],
				   st->dns1[0], st->dns1[1], st->dns1[2], st->dns1[3],
				   st->dns2[0], st->dns2[1], st->dns2[2], st->dns2[3]);
			fflush(stdout);
		}
	}
	else if (msg_type == DHCP_MSG_INFORM)
	{
		resp->ciaddr = req->ciaddr;
		memcpy(&resp->siaddr, st->server_ip, 4);

		uint8_t rtype = DHCP_MSG_ACK;
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 53, 1, &rtype);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 54, 4, st->server_ip);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 1, 4, subnet_mask);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 3, 4, st->server_ip);
		dhcp_opt_append(resp->options, opt_cap, &opt_pos, 6, 8, dns_pair);
		resp->options[opt_pos++] = 255;

		if (req->ciaddr != 0)
		{
			if (send_broadcast_out)
				*send_broadcast_out = 0;
			if (unicast_ip_out)
				memcpy(unicast_ip_out, &req->ciaddr, 4);
		}
		else if (send_broadcast_out)
		{
			*send_broadcast_out = 1;
		}
	}
	else
	{
		return 0;
	}

	size_t total_len = fixed_hdr_len + opt_pos;
	if (total_len < 300)
		total_len = 300;
	return (ssize_t)total_len;
}

void* dhcp_server_thread(void* arg)
{
	DHCPThreadArg* darg = (DHCPThreadArg*)arg;
	if (darg == NULL || darg->cfg == NULL || darg->running == NULL)
		return NULL;

	RouterConfig* cfg = darg->cfg;
	if (!cfg->has_lan_ip)
	{
		fprintf(stderr, "[DHCP] WARN: LAN(%s) IPv4 주소가 없어 DHCP 서버를 시작하지 않습니다.\n",
				cfg->lan_if);
		return NULL;
	}

	int dsock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (dsock < 0)
	{
		perror("[DHCP] socket(UDP) failed");
		return NULL;
	}

	int one = 1;
	setsockopt(dsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	setsockopt(dsock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));

	/* LAN 인터페이스(eth0)에만 바인딩하여 WAN(wlan0) 공유기 망과 충돌 원천 차단 */
	if (setsockopt(dsock, SOL_SOCKET, SO_BINDTODEVICE,
				   cfg->lan_if, (socklen_t)(strlen(cfg->lan_if) + 1)) < 0)
	{
		perror("[DHCP] setsockopt(SO_BINDTODEVICE) failed");
		close(dsock);
		return NULL;
	}

	struct sockaddr_in bind_addr = {0};
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(DHCP_SERVER_PORT);
	bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(dsock, (const struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0)
	{
		perror("[DHCP] bind(0.0.0.0:67) failed");
		close(dsock);
		return NULL;
	}

	DHCPServerState state;
	dhcp_state_init(&state, cfg->lan_ip);

	printf("[DHCP] Server active on %s:67 (pool=%u.%u.%u.%d-%d, gw=%u.%u.%u.%u, dns=%u.%u.%u.%u/%u.%u.%u.%u)\n",
		   cfg->lan_if,
		   cfg->lan_ip[0], cfg->lan_ip[1], cfg->lan_ip[2], DHCP_POOL_START, DHCP_POOL_END,
		   cfg->lan_ip[0], cfg->lan_ip[1], cfg->lan_ip[2], cfg->lan_ip[3],
		   state.dns1[0], state.dns1[1], state.dns1[2], state.dns1[3],
		   state.dns2[0], state.dns2[1], state.dns2[2], state.dns2[3]);
	fflush(stdout);

	uint8_t req_buf[1500];
	uint8_t resp_buf[sizeof(DHCPPacket)];

	while (*(darg->running))
	{
		struct pollfd pfds[2];
		nfds_t nfds = 1;
		pfds[0].fd = dsock;
		pfds[0].events = POLLIN;
		pfds[0].revents = 0;
		if (darg->stop_efd >= 0)
		{
			pfds[1].fd = darg->stop_efd;
			pfds[1].events = POLLIN;
			pfds[1].revents = 0;
			nfds = 2;
		}

		int prc = poll(pfds, nfds, 500);
		if (prc < 0)
		{
			if (errno == EINTR)
				continue;
			perror("[DHCP] poll failed");
			break;
		}
		if (prc == 0)
			continue;
		if (nfds == 2 && (pfds[1].revents & POLLIN))
			break;
		if (!(pfds[0].revents & POLLIN))
			continue;

		struct sockaddr_in cli_addr = {0};
		socklen_t cli_len = sizeof(cli_addr);
		ssize_t rlen = recvfrom(dsock, req_buf, sizeof(req_buf), 0,
								(struct sockaddr*)&cli_addr, &cli_len);
		if (rlen < 0)
		{
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			perror("[DHCP] recvfrom failed");
			break;
		}

		int send_bcast = 1;
		uint8_t ucast_ip[4] = {0};
		ssize_t slen = dhcp_handle_request(&state, cfg,
										   req_buf, (size_t)rlen,
										   resp_buf, sizeof(resp_buf),
										   &send_bcast, ucast_ip);
		if (slen <= 0)
			continue;

		struct sockaddr_in dst = {0};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(DHCP_CLIENT_PORT);
		if (send_bcast)
			dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);
		else
			memcpy(&dst.sin_addr.s_addr, ucast_ip, 4);

		if (sendto(dsock, resp_buf, (size_t)slen, 0,
				   (const struct sockaddr*)&dst, sizeof(dst)) < 0)
		{
			if (errno != EINTR && errno != EAGAIN)
				perror("[DHCP] sendto failed");
		}
	}

	close(dsock);
	return NULL;
}

/* =========================================================================
 * 네트워크 인터페이스 / 소켓 / 라우팅 / ARP / 출력 유틸리티
 * ========================================================================= */

int enable_promisc(int sock, int ifindex)
{
	struct packet_mreq mreq = {0};
	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	return setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
}

int disable_promisc(int sock, int ifindex)
{
	struct packet_mreq mreq = {0};
	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	return setsockopt(sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
}

int get_if_mac(int sock, const char* ifname, uint8_t mac_out[6])
{
	if (ifname == NULL || mac_out == NULL)
		return -1;

	struct ifreq ifr = {0};
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
		return -1;

	memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}

int get_if_ipv4(int sock, const char* ifname, uint8_t ip_out[4])
{
	if (ifname == NULL || ip_out == NULL)
		return -1;

	struct ifreq ifr = {0};
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_addr.sa_family = AF_INET;

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
		return -1;

	const struct sockaddr_in* sin = (const struct sockaddr_in*)&ifr.ifr_addr;
	memcpy(ip_out, &sin->sin_addr.s_addr, 4);
	return 0;
}

int get_default_gw_ipv4(const char* ifname, uint8_t gw_ip_out[4])
{
	if (ifname == NULL || gw_ip_out == NULL)
		return -1;

	FILE* fp = fopen("/proc/net/route", "r");
	if (fp == NULL)
		return -1;

	char line[256];
	int found = 0;

	/* 헤더 라인 건너뛰기 */
	if (fgets(line, sizeof(line), fp) != NULL)
	{
		while (fgets(line, sizeof(line), fp) != NULL)
		{
			char iface[IFNAMSIZ];
			unsigned long dest = 0, gw = 0;
			unsigned int flags = 0;

			if (sscanf(line, "%15s %lx %lx %x", iface, &dest, &gw, &flags) == 4)
			{
				if (strcmp(iface, ifname) == 0 && dest == 0 && gw != 0)
				{
					uint32_t gw32 = (uint32_t)gw;
					memcpy(gw_ip_out, &gw32, 4);
					found = 1;
					break;
				}
			}
		}
	}

	fclose(fp);
	return found ? 0 : -1;
}

int parse_mac_str(const char* str, uint8_t mac_out[6])
{
	if (str == NULL || mac_out == NULL)
		return -1;

	unsigned int b[6];
	if (sscanf(str, "%x:%x:%x:%x:%x:%x",
			   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
		return -1;

	for (int i = 0; i < 6; i++)
	{
		if (b[i] > 0xFF)
			return -1;
		mac_out[i] = (uint8_t)b[i];
	}
	return 0;
}

int get_arp_mac(const char* ifname, const uint8_t ip[4], uint8_t mac_out[6])
{
	if (ifname == NULL || ip == NULL || mac_out == NULL)
		return -1;

	char target_ip[INET_ADDRSTRLEN];
	snprintf(target_ip, sizeof(target_ip), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);

	FILE* fp = fopen("/proc/net/arp", "r");
	if (fp == NULL)
		return -1;

	char line[256];
	int found = 0;

	if (fgets(line, sizeof(line), fp) != NULL)
	{
		while (fgets(line, sizeof(line), fp) != NULL)
		{
			char ip_str[64], hw_type[16], flags[16], mac_str[32], mask[32], dev[IFNAMSIZ];
			if (sscanf(line, "%63s %15s %15s %31s %31s %15s",
					   ip_str, hw_type, flags, mac_str, mask, dev) == 6)
			{
				if (strcmp(ip_str, target_ip) == 0 && strcmp(dev, ifname) == 0)
				{
					uint8_t parsed[6];
					uint8_t zero[6] = {0};
					if (parse_mac_str(mac_str, parsed) == 0 && memcmp(parsed, zero, 6) != 0)
					{
						memcpy(mac_out, parsed, 6);
						found = 1;
						break;
					}
				}
			}
		}
	}

	fclose(fp);
	return found ? 0 : -1;
}

int router_config_init(int sock, RouterConfig* cfg, const char* lan_if, const char* wan_if,
                       const char* gw_ip_override, const char* gw_mac_override)
{
	if (cfg == NULL || lan_if == NULL || wan_if == NULL)
		return -1;

	memset(cfg, 0, sizeof(*cfg));
	pthread_mutex_init(&cfg->fwd_lock, NULL);
	strncpy(cfg->lan_if, lan_if, IFNAMSIZ - 1);
	strncpy(cfg->wan_if, wan_if, IFNAMSIZ - 1);

	cfg->lan_ifindex = (int)if_nametoindex(cfg->lan_if);
	if (cfg->lan_ifindex == 0)
	{
		fprintf(stderr, "LAN interface not found: %s\n", cfg->lan_if);
		return -1;
	}

	cfg->wan_ifindex = (int)if_nametoindex(cfg->wan_if);
	if (cfg->wan_ifindex == 0)
	{
		fprintf(stderr, "WAN interface not found: %s\n", cfg->wan_if);
		return -1;
	}

	if (get_if_mac(sock, cfg->lan_if, cfg->lan_mac) < 0)
	{
		fprintf(stderr, "Failed to get LAN MAC (%s)\n", cfg->lan_if);
		return -1;
	}

	if (get_if_mac(sock, cfg->wan_if, cfg->wan_mac) < 0)
	{
		fprintf(stderr, "Failed to get WAN MAC (%s)\n", cfg->wan_if);
		return -1;
	}

	cfg->has_lan_ip = (get_if_ipv4(sock, cfg->lan_if, cfg->lan_ip) == 0);

	int has_ip = (get_if_ipv4(sock, cfg->wan_if, cfg->wan_ip) == 0);

	int has_gw_ip = 0;
	if (gw_ip_override != NULL)
	{
		struct in_addr addr;
		if (inet_pton(AF_INET, gw_ip_override, &addr) == 1)
		{
			memcpy(cfg->gw_ip, &addr.s_addr, 4);
			has_gw_ip = 1;
		}
	}
	else if (get_default_gw_ipv4(cfg->wan_if, cfg->gw_ip) == 0)
	{
		has_gw_ip = 1;
	}

	int has_gw_mac = 0;
	if (gw_mac_override != NULL)
	{
		has_gw_mac = (parse_mac_str(gw_mac_override, cfg->gw_mac) == 0);
	}
	else if (has_gw_ip && get_arp_mac(cfg->wan_if, cfg->gw_ip, cfg->gw_mac) == 0)
	{
		has_gw_mac = 1;
	}

	cfg->has_wan_l3 = (has_ip && has_gw_mac);
	return 0;
}

int router_config_set_port_fwd(RouterConfig* cfg, const char* lan_ip_str,
                               uint16_t wan_port_host, uint16_t lan_port_host)
{
	if (cfg == NULL || lan_ip_str == NULL || wan_port_host == 0 || lan_port_host == 0)
		return -1;

	struct in_addr addr;
	if (inet_pton(AF_INET, lan_ip_str, &addr) != 1)
		return -1;

	memcpy(cfg->fwd_lan_ip, &addr.s_addr, 4);
	cfg->fwd_wan_port = htons(wan_port_host);
	cfg->fwd_lan_port = htons(lan_port_host);
	cfg->has_fwd_lan_mac = (get_arp_mac(cfg->lan_if, cfg->fwd_lan_ip, cfg->fwd_lan_mac) == 0);
	cfg->has_port_fwd = 1;
	return 0;
}

void print_mac(const uint8_t m[6])
{
	if (m == NULL)
		return;
	printf("%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void router_print_status(const RouterConfig* cfg, const char* prog_name)
{
	if (cfg == NULL)
		return;

	printf("=== L3 Switch/Router (NAT: TCP/UDP/ICMP + PortFwd) + IDS Thread Started ===\n");
	printf("LAN: %s (ifindex=%d, MAC=", cfg->lan_if, cfg->lan_ifindex);
	print_mac(cfg->lan_mac);
	if (cfg->has_lan_ip)
		printf(", IP=%u.%u.%u.%u", cfg->lan_ip[0], cfg->lan_ip[1], cfg->lan_ip[2], cfg->lan_ip[3]);
	printf(")\n");

	printf("WAN: %s (ifindex=%d, MAC=", cfg->wan_if, cfg->wan_ifindex);
	print_mac(cfg->wan_mac);
	if (cfg->has_wan_l3)
	{
		printf(", IP=%u.%u.%u.%u, GW_MAC=",
			   cfg->wan_ip[0], cfg->wan_ip[1], cfg->wan_ip[2], cfg->wan_ip[3]);
		print_mac(cfg->gw_mac);
		printf(")\n");
		printf("NAT Port Pool: %d-%d (TCP/UDP/ICMP, outside ephemeral 32768-60999)\n",
			   NAT_PORT_MIN, NAT_PORT_MAX);
	}
	else
	{
		printf(")\n[WARN] WAN(%s) IP 또는 게이트웨이 MAC을 찾지 못해 모니터링/IDS 모드로 동작합니다.\n",
			   cfg->wan_if);
		printf("       외부 포워딩을 활성화하려면 %s 연결 후 재실행하거나 인자로 지정하세요:\n",
			   cfg->wan_if);
		printf("       sudo %s <lan_if> <wan_if> [fwd_port] [fwd_lan_ip] [gw_ip] [gw_mac] [ids_log]\n",
			   prog_name ? prog_name : "./server");
	}

	if (cfg->has_port_fwd)
	{
		printf("Port Forward: WAN TCP:%u -> %u.%u.%u.%u:%u (MAC=",
			   (unsigned)ntohs(cfg->fwd_wan_port),
			   cfg->fwd_lan_ip[0], cfg->fwd_lan_ip[1], cfg->fwd_lan_ip[2], cfg->fwd_lan_ip[3],
			   (unsigned)ntohs(cfg->fwd_lan_port));
		if (cfg->has_fwd_lan_mac)
			print_mac(cfg->fwd_lan_mac);
		else
			printf("ARP-pending");
		printf(")\n");
	}
}
