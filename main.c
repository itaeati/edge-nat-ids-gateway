#include "header.h"

static volatile sig_atomic_t g_running = 1;
static int g_stop_efd = -1;

static void handle_signal(int sig)
{
	(void)sig;
	g_running = 0;
	if (g_stop_efd >= 0)
	{
		uint64_t one = 1;
		ssize_t wr = write(g_stop_efd, &one, sizeof(one));
		(void)wr;
	}
}

int main(int argc, char* argv[])
{
	/* 사용법: sudo ./server [lan_if] [wan_if] [fwd_port] [fwd_lan_ip] [gw_ip] [gw_mac] [ids_log_path] */
	const char* lan_if = (argc >= 2) ? argv[1] : "eth0";
	const char* wan_if = (argc >= 3) ? argv[2] : "wlan0";
	int fwd_port = (argc >= 4) ? atoi(argv[3]) : DEFAULT_FWD_PORT;
	const char* fwd_lan_ip = (argc >= 5) ? argv[4] : DEFAULT_FWD_LAN_IP;
	const char* gw_ip_override = (argc >= 6) ? argv[5] : NULL;
	const char* gw_mac_override = (argc >= 7) ? argv[6] : NULL;
	const char* ids_log_path = (argc >= 8) ? argv[7] : IDS_DEFAULT_LOG_PATH;

	int exit_code = -1;
	int hsock = -1;
	int cfg_inited = 0;
	int lan_promisc = 0;
	int wan_promisc = 0;
	int nat_inited = 0;
	int ids_inited = 0;
	int queue_inited = 0;
	int gc_started = 0;
	int ids_started = 0;
	int dhcp_started = 0;

	RouterConfig cfg;
	table* nat_table = NULL;
	IDSContext ids_ctx;
	PacketQueue* pkt_queue = NULL;
	pthread_t gc_tid;
	pthread_t ids_tid;
	pthread_t dhcp_tid;

	/* Ctrl+C(SIGINT)/SIGTERM 즉시 전파용 eventfd 생성 */
	g_stop_efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (g_stop_efd < 0)
	{
		perror("eventfd failed");
		goto cleanup;
	}

	struct sigaction sa = {0};
	sa.sa_handler = handle_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	hsock = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (hsock < 0)
	{
		perror("socket(AF_PACKET) failed (sudo 권한 필요)");
		goto cleanup;
	}

	if (router_config_init(hsock, &cfg, lan_if, wan_if, gw_ip_override, gw_mac_override) < 0)
		goto cleanup;
	cfg_inited = 1;

	if (fwd_port > 0 && fwd_port <= 65535 && fwd_lan_ip != NULL && fwd_lan_ip[0] != '\0')
	{
		if (router_config_set_port_fwd(&cfg, fwd_lan_ip, (uint16_t)fwd_port, (uint16_t)fwd_port) < 0)
			fprintf(stderr, "[WARN] 포트 포워딩 설정 실패 (%s:%d)\n", fwd_lan_ip, fwd_port);
	}

	if (enable_promisc(hsock, cfg.lan_ifindex) < 0)
	{
		perror("setsockopt PROMISC (LAN) failed");
		goto cleanup;
	}
	lan_promisc = 1;

	if (cfg.wan_ifindex != cfg.lan_ifindex)
	{
		if (enable_promisc(hsock, cfg.wan_ifindex) < 0)
		{
			perror("setsockopt PROMISC (WAN) failed");
			goto cleanup;
		}
		wan_promisc = 1;
	}

	router_print_status(&cfg, argv[0]);

	nat_table = malloc(sizeof(table));
	if (nat_table == NULL)
	{
		perror("nat_table malloc failed");
		goto cleanup;
	}
	nat_table_init(nat_table);
	nat_inited = 1;

	if (ids_init(&ids_ctx, ids_log_path) < 0)
		perror("ids log file open failed (stderr 출력만 유지)");
	else
		printf("IDS Log: %s\n", ids_log_path);
	ids_inited = 1;

	pkt_queue = calloc(1, sizeof(PacketQueue));
	if (pkt_queue == NULL)
	{
		perror("pkt_queue calloc failed");
		goto cleanup;
	}
	pkt_queue_init(pkt_queue);
	queue_inited = 1;

	/* 워커 스레드는 SIGINT/SIGTERM을 마스킹해 메인 스레드가 시그널을 확정 수신하도록 보장 */
	sigset_t sigmask, oldmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &sigmask, &oldmask);

	/* 1) NAT 세션 만료 정리 스레드 시작 */
	NatGCArg gc_arg = {
		.nat_table = nat_table,
		.running = &g_running,
		.stop_efd = g_stop_efd,
	};
	int gc_ret = pthread_create(&gc_tid, NULL, nat_gc_thread, &gc_arg);
	if (gc_ret != 0)
	{
		pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
		fprintf(stderr, "pthread_create(gc) failed: %s\n", strerror(gc_ret));
		goto cleanup;
	}
	gc_started = 1;

	/* 2) 전용 IDS 검사 + NAT 포워딩 워커 스레드 시작 */
	WorkerArg worker_arg = {0};
	worker_arg.hsock = hsock;
	worker_arg.cfg = &cfg;
	worker_arg.nat_table = nat_table;
	worker_arg.ids_ctx = &ids_ctx;
	worker_arg.queue = pkt_queue;
	worker_arg.wan_dst.sll_family = AF_PACKET;
	worker_arg.wan_dst.sll_protocol = htons(ETH_P_IP);
	worker_arg.wan_dst.sll_ifindex = cfg.wan_ifindex;
	worker_arg.lan_dst.sll_family = AF_PACKET;
	worker_arg.lan_dst.sll_protocol = htons(ETH_P_IP);
	worker_arg.lan_dst.sll_ifindex = cfg.lan_ifindex;

	int ids_ret = pthread_create(&ids_tid, NULL, ids_worker_thread, &worker_arg);
	if (ids_ret != 0)
	{
		pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
		fprintf(stderr, "pthread_create(ids_worker) failed: %s\n", strerror(ids_ret));
		goto cleanup;
	}
	ids_started = 1;

	/* 3) 내장 LAN DHCPv4 서버 스레드 시작 (eth0 전용, UDP 67/68) */
	DHCPThreadArg dhcp_arg = {
		.cfg = &cfg,
		.running = &g_running,
		.stop_efd = g_stop_efd,
	};
	int dhcp_ret = pthread_create(&dhcp_tid, NULL, dhcp_server_thread, &dhcp_arg);
	if (dhcp_ret != 0)
		fprintf(stderr, "pthread_create(dhcp) failed: %s (DHCP 없이 계속 진행)\n", strerror(dhcp_ret));
	else
		dhcp_started = 1;

	/* 메인 스레드에서만 SIGINT/SIGTERM 수신 복원 */
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);

	printf("Worker Threads: IDS+NAT Worker Thread, NAT-GC Thread%s active\n",
		   dhcp_started ? ", LAN DHCPv4 Server Thread" : "");
	fflush(stdout);

	uint8_t buffer[65536];

	while (g_running)
	{
		struct pollfd pfds[2];
		pfds[0].fd = hsock;
		pfds[0].events = POLLIN;
		pfds[0].revents = 0;
		pfds[1].fd = g_stop_efd;
		pfds[1].events = POLLIN;
		pfds[1].revents = 0;

		int prc = poll(pfds, 2, 500);
		if (prc < 0)
		{
			if (errno == EINTR)
				continue;
			perror("poll(raw_sock) failed");
			break;
		}
		if (prc == 0)
			continue;
		if (pfds[1].revents & POLLIN)
			break;
		if (!(pfds[0].revents & POLLIN))
			continue;

		struct sockaddr_ll src_addr = {0};
		socklen_t addr_len = sizeof(src_addr);

		ssize_t len = recvfrom(hsock, buffer, sizeof(buffer), 0,
							   (struct sockaddr*)&src_addr, &addr_len);
		if (len < 0)
		{
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			perror("recvfrom failed");
			break;
		}

		/* 자신이 송신한 프레임이 다시 올라오는 루프 방지 */
		if (src_addr.sll_pkttype == PACKET_OUTGOING)
			continue;

		/* LAN 또는 WAN에서 들어온 프레임만 처리 (lo 등 무시) */
		int is_from_lan = (src_addr.sll_ifindex == cfg.lan_ifindex);
		int is_from_wan = (src_addr.sll_ifindex == cfg.wan_ifindex);
		if (!is_from_lan && !is_from_wan)
			continue;

		if ((size_t)len < sizeof(Frame) + sizeof(Packet) || (size_t)len > PKT_MAX_FRAME)
			continue;

		const Frame* pether = (const Frame*)buffer;
		if (ntohs(pether->protocol) != ETH_P_IP)
			continue;

		const Packet* pip = (const Packet*)(buffer + sizeof(Frame));
		if (pip->protocol != IPPROTO_TCP &&
			pip->protocol != IPPROTO_UDP &&
			pip->protocol != IPPROTO_ICMP)
			continue;

		/* 수신 프레임을 전용 IDS+NAT 스레드 큐로 전달 */
		pkt_queue_push(pkt_queue, buffer, (size_t)len, is_from_lan, time(NULL));
	}

	exit_code = 0;
	printf("\n[SHUTDOWN] Signal received — stopping threads and closing all file descriptors...\n");
	fflush(stdout);

cleanup:
	/* 모든 워커 스레드에 즉시 종료 신호 전파 */
	g_running = 0;
	if (g_stop_efd >= 0)
	{
		uint64_t one = 1;
		ssize_t wr = write(g_stop_efd, &one, sizeof(one));
		(void)wr;
	}
	if (queue_inited && pkt_queue != NULL)
		pkt_queue_stop(pkt_queue);

	/* 1) 모든 스레드가 소켓·로그 FD 사용을 끝낼 때까지 대기 */
	if (ids_started)
		pthread_join(ids_tid, NULL);
	if (gc_started)
		pthread_join(gc_tid, NULL);
	if (dhcp_started)
		pthread_join(dhcp_tid, NULL); /* dsock은 dhcp_server_thread 종료 직전 close 완료 */

	/* 2) promiscuous 모드 해제 및 raw 소켓 FD 정리 */
	if (hsock >= 0)
	{
		if (lan_promisc)
			disable_promisc(hsock, cfg.lan_ifindex);
		if (wan_promisc)
			disable_promisc(hsock, cfg.wan_ifindex);
		close(hsock);
		hsock = -1;
	}

	/* 3) IDS 로그 파일 FD flush + fclose */
	if (ids_inited)
		ids_destroy(&ids_ctx);

	/* 4) 큐·NAT 테이블·뮤텍스 메모리 정리 */
	if (queue_inited && pkt_queue != NULL)
		pkt_queue_destroy(pkt_queue);
	free(pkt_queue);
	if (nat_inited && nat_table != NULL)
		destroy(nat_table);
	free(nat_table);
	if (cfg_inited)
		pthread_mutex_destroy(&cfg.fwd_lock);

	/* 5) eventfd 종료 */
	if (g_stop_efd >= 0)
	{
		close(g_stop_efd);
		g_stop_efd = -1;
	}

	if (exit_code == 0)
	{
		printf("[SHUTDOWN] Clean exit complete (raw_sock, dhcp_sock, ids_log, stop_efd all closed).\n");
		fflush(stdout);
	}
	return exit_code;
}
