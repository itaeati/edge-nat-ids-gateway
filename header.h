#ifndef HEADER_H
#define HEADER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>

/* TCP 플래그 비트 (ntohs(ptcp->flags) 하위 8비트 기준) */
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

/* NAT 설정 상수 (리눅스 임시 포트 32768~60999 및 서비스 포트 25000과 충돌 방지) */
#define NAT_PORT_MIN        26000
#define NAT_PORT_MAX        31000
#define NAT_TIMEOUT_SEC     120
#define NAT_GC_INTERVAL_SEC 10

/* 기본 포트 포워딩 설정 (WAN -> 내부 젯슨 서버) */
#define DEFAULT_FWD_LAN_IP  "192.168.100.2"
#define DEFAULT_FWD_PORT    25000

/* IDS/포워딩 워커 스레드 패킷 큐 설정 */
#define PKT_QUEUE_CAP       256
#define PKT_MAX_FRAME       2048

/* 내장 DHCPv4 서버 설정 (LAN 전용, RFC 2131) */
#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68
#define DHCP_POOL_START     2      /* .2  (예: 192.168.100.2) */
#define DHCP_POOL_END       50     /* .50 (예: 192.168.100.50) */
#define DHCP_POOL_SIZE      (DHCP_POOL_END - DHCP_POOL_START + 1)
#define DHCP_LEASE_SEC      3600
#define DHCP_MAGIC_COOKIE   0x63825363u

#define DHCP_MSG_DISCOVER   1
#define DHCP_MSG_OFFER      2
#define DHCP_MSG_REQUEST    3
#define DHCP_MSG_DECLINE    4
#define DHCP_MSG_ACK        5
#define DHCP_MSG_NAK        6
#define DHCP_MSG_RELEASE    7
#define DHCP_MSG_INFORM     8

/* IDS 설정 상수 */
#define IDS_TRACK_SLOTS      256
#define IDS_WINDOW_SEC       5
#define IDS_SYN_FLOOD_LIMIT  50
#define IDS_PORT_SCAN_LIMIT  20
#define IDS_DEFAULT_LOG_PATH "ids_alerts.log"

#pragma pack(push, 1)

typedef struct MACHeader {
	uint8_t dstMac[6];
	uint8_t srcMac[6];
	uint16_t protocol;
} Frame;

typedef struct IPHeader {
	uint8_t verihl;
	uint8_t tos;
	uint16_t length;
	uint16_t id;
	uint16_t offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;

	uint8_t srcip[4];
	uint8_t dstip[4];
} Packet;

typedef struct TCPHeader {
	uint16_t srcport;
	uint16_t dstport;
	uint32_t seq;
	uint32_t ack;
	uint16_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t Urgent;
} Segment;

typedef struct UDPHeader {
	uint16_t srcport;
	uint16_t dstport;
	uint16_t length;
	uint16_t checksum;
} UdpHeader;

typedef struct ICMPHeader {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t id;
	uint16_t seq;
} IcmpHeader;

typedef struct DHCPPacket {
	uint8_t  op;
	uint8_t  htype;
	uint8_t  hlen;
	uint8_t  hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t  chaddr[16];
	uint8_t  sname[64];
	uint8_t  file[128];
	uint32_t magic;
	uint8_t  options[312];
} DHCPPacket;

typedef struct PsuedoHeader {
	uint8_t srcip[4];
	uint8_t dstip[4];
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
} psuedo;

#pragma pack(pop)

typedef struct NODE {
	uint8_t srcip[4];
	uint8_t dstip[4];
	uint8_t srcMac[6];
	uint8_t peer_mac[6];
	uint8_t has_peer_mac;

	uint16_t srcport;
	uint16_t dstport;
	uint16_t natport;

	uint8_t protocol;
	uint8_t flags;

	time_t time;
	uint32_t seq;
	uint32_t ack;

	struct NODE* next;
} node;

typedef struct NAT_Table {
	int size;
	uint8_t prior;
	uint16_t next_port;
	pthread_mutex_t lock;

	node* head;
} table;

typedef struct RouterConfig {
	char lan_if[IFNAMSIZ];
	char wan_if[IFNAMSIZ];
	int lan_ifindex;
	int wan_ifindex;

	uint8_t lan_mac[6];
	uint8_t lan_ip[4];
	int has_lan_ip;

	uint8_t wan_mac[6];
	uint8_t wan_ip[4];
	uint8_t gw_ip[4];
	uint8_t gw_mac[6];
	int has_wan_l3;

	/* 정적 포트 포워딩 (WAN -> LAN 젯슨 서버) */
	int has_port_fwd;
	uint8_t fwd_lan_ip[4];
	uint8_t fwd_lan_mac[6];
	int has_fwd_lan_mac;
	uint16_t fwd_wan_port; /* network byte order */
	uint16_t fwd_lan_port; /* network byte order */
	pthread_mutex_t fwd_lock;
} RouterConfig;

typedef struct DHCPLease {
	int in_use;
	uint8_t mac[6];
	uint8_t ip[4];
	time_t expire_at;
} DHCPLease;

typedef struct DHCPServerState {
	DHCPLease leases[DHCP_POOL_SIZE];
	uint8_t server_ip[4];
	uint8_t dns1[4];
	uint8_t dns2[4];
} DHCPServerState;

typedef struct DHCPThreadArg {
	RouterConfig* cfg;
	volatile sig_atomic_t* running;
	int stop_efd;
} DHCPThreadArg;

typedef struct NatGCArg {
	table* nat_table;
	volatile sig_atomic_t* running;
	int stop_efd;
} NatGCArg;

typedef struct IDSHostEntry {
	int in_use;
	uint8_t srcip[4];
	time_t window_start;
	uint32_t syn_count;
	uint32_t port_count;
	uint16_t recent_ports[IDS_PORT_SCAN_LIMIT];
} IDSHostEntry;

typedef struct IDSContext {
	IDSHostEntry hosts[IDS_TRACK_SLOTS];
	FILE* log_fp;
	pthread_mutex_t lock;
} IDSContext;

typedef enum IDSResult {
	IDS_ALLOW = 0,
	IDS_ALERT_DROP = 1
} IDSResult;

typedef struct PacketItem {
	uint8_t data[PKT_MAX_FRAME];
	size_t len;
	int is_from_lan;
	time_t rx_time;
} PacketItem;

typedef struct PacketQueue {
	PacketItem items[PKT_QUEUE_CAP];
	int head;
	int tail;
	int count;
	int stopped;
	pthread_mutex_t lock;
	pthread_cond_t not_empty;
} PacketQueue;

typedef struct WorkerArg {
	int hsock;
	RouterConfig* cfg;
	table* nat_table;
	IDSContext* ids_ctx;
	PacketQueue* queue;
	struct sockaddr_ll wan_dst;
	struct sockaddr_ll lan_dst;
} WorkerArg;

/* 체크섬 계산 */
uint16_t packet_checksum(Packet* pip);
uint16_t segment_checksum(Packet* pip, Segment* ptcp);
uint16_t udp_checksum(Packet* pip, UdpHeader* pudp);
uint16_t icmp_checksum(const uint8_t* data, size_t len);

/* NAT 테이블 관리 및 정리 스레드 */
void nat_table_init(table* tbl);
int nat_table_add(table* tbl, const uint8_t* Pack);
int nat_table_rem(table* tbl, const uint8_t* ip);
int nat_table_expire(table* tbl, time_t now, int timeout_sec);
void* nat_gc_thread(void* arg);
void destroy(table* tbl);

/* L3/L4 NAT 변환 (0: 포워딩 가능, 1: 대상 아님/무시, -1: 에러/드롭) */
int nat_outbound_snat(RouterConfig* cfg, table* tbl, uint8_t* frame_buf, size_t frame_len);
int nat_inbound_dnat(RouterConfig* cfg, table* tbl, uint8_t* frame_buf, size_t frame_len);

/* IDS 탐지·로그 및 전용 IDS/포워딩 스레드 */
int ids_init(IDSContext* ctx, const char* log_path);
void ids_destroy(IDSContext* ctx);
IDSResult ids_inspect_tcp(IDSContext* ctx, const Packet* pip, const Segment* ptcp,
                          size_t ip_avail, time_t now, const char** reason_out);
void ids_log_alert(IDSContext* ctx, const char* direction, const char* reason,
                   const Frame* eth, const Packet* pip, const Segment* ptcp, time_t now);
void pkt_queue_init(PacketQueue* q);
int pkt_queue_push(PacketQueue* q, const uint8_t* data, size_t len, int is_from_lan, time_t rx_time);
int pkt_queue_pop(PacketQueue* q, PacketItem* out);
void pkt_queue_stop(PacketQueue* q);
void pkt_queue_destroy(PacketQueue* q);
void* ids_worker_thread(void* arg);

/* 내장 LAN DHCPv4 서버 스레드 및 패킷 처리 */
void dhcp_state_init(DHCPServerState* st, const uint8_t server_ip[4]);
ssize_t dhcp_handle_request(DHCPServerState* st, RouterConfig* cfg,
                            const uint8_t* req_buf, size_t req_len,
                            uint8_t* resp_buf, size_t resp_cap,
                            int* send_broadcast_out, uint8_t unicast_ip_out[4]);
void* dhcp_server_thread(void* arg);

/* 네트워크 인터페이스·소켓·출력 유틸리티 */
int enable_promisc(int sock, int ifindex);
int disable_promisc(int sock, int ifindex);
int get_if_mac(int sock, const char* ifname, uint8_t mac_out[6]);
int get_if_ipv4(int sock, const char* ifname, uint8_t ip_out[4]);
int get_default_gw_ipv4(const char* ifname, uint8_t gw_ip_out[4]);
int get_arp_mac(const char* ifname, const uint8_t ip[4], uint8_t mac_out[6]);
int parse_mac_str(const char* str, uint8_t mac_out[6]);
int router_config_init(int sock, RouterConfig* cfg, const char* lan_if, const char* wan_if,
                       const char* gw_ip_override, const char* gw_mac_override);
int router_config_set_port_fwd(RouterConfig* cfg, const char* lan_ip_str,
                               uint16_t wan_port_host, uint16_t lan_port_host);
void print_mac(const uint8_t m[6]);
void router_print_status(const RouterConfig* cfg, const char* prog_name);

#endif
