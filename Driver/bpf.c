#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/string.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define FILECACHE_PORT 	6666
#define FILECACHE_MTU 	1472
#define FILECACHE_CMD_READ 		0x0000
#define FILECACHE_CMD_LOAD    0x0001

struct filecache_req
{
	__u16 cmd;
	__u8 req[];
} __attribute__((__packed__));

struct filecache_read_req
{
	__u16 cmd;
	__u32 key;
	__u64 pos;
	__u32 len;
	__u32 id;
	__u32 flags;
} __attribute__((__packed__));

struct filecache_load_req 
{
	__u16 cmd;
	__u32 key;
	__u64 pos;
	__u32 len;
	__u32 id;
} __attribute__((__packed__));

extern int bpf_filecache_load(__u32 key, __u64 pos, __u32 len, __u32 id) __ksym;
extern int bpf_filecache_read(struct filecache_read_req *req, char *buf, int buf__sz) __ksym;

static __always_inline void adjust_eth_hdr(void *data)
{
	struct ethhdr *eth = (struct ethhdr *)data;
	unsigned char tmp[ETH_ALEN];

	memcpy(tmp, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, tmp, ETH_ALEN);
}

static __always_inline void adjust_ip_hdr(void *data, void *data_end)
{
	struct iphdr *ip = data + sizeof(struct ethhdr);
	__be32 tmp_ip, csum;

	tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;
	ip->tot_len = bpf_htons(data_end - data - sizeof(struct ethhdr));
	ip->check = 0;
	csum = bpf_csum_diff(0, 0, (void *)ip, sizeof(*ip), 0);
	csum += (csum << 16) + (csum >> 16);
	csum = ~csum >> 16;
	ip->check = csum;
}

static __always_inline void adjust_udp_hdr(void *data, void *data_end) 
{
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	__be16 tmp_port;

	tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;
	udp->len = bpf_htons(data_end - data - sizeof(struct ethhdr) - sizeof(struct iphdr));
	udp->check = 0;
}

SEC("fc")
int filecache(struct xdp_md *ctx)
{
	void *data 										 = (void *)(long)ctx->data;
	void *data_end 								 = (void *)(long)ctx->data_end;
	unsigned int data_sz 					 = data_end - data;
	struct ethhdr *eth 						 = data;
	struct iphdr *ip 							 = data + sizeof(*eth);
	struct udphdr *udp 						 = data + sizeof(*eth) + sizeof(*ip);
	struct filecache_req *req = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
	struct filecache_read_req *read;
	struct filecache_load_req *load;

	// check if this is filecache packet
	if (data_end < (void *)req + sizeof(*req)) {
		return XDP_PASS;
	}

	if (ip->protocol != IPPROTO_UDP) {
		return XDP_PASS;
	}

	if (bpf_ntohs(udp->len) < sizeof(*req)) {
		return XDP_PASS;
	}

	if (bpf_ntohs(udp->dest) != FILECACHE_PORT) {
		return XDP_PASS;
	}

	// extend packet length
	if (bpf_xdp_adjust_tail(ctx, FILECACHE_MTU - data_sz) < 0) {
		return XDP_PASS;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;	
	data_sz = data_end - data;

	if (data_end < data + FILECACHE_MTU) {
		return XDP_PASS;
	}
	
	// prepare packet for processing
	char *payload = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
	unsigned int payload_sz = data_end - (void *)payload;

	if (payload_sz < FILECACHE_MTU - sizeof(*eth) - sizeof(*ip) - sizeof(*udp)) {
		return XDP_PASS;
	}

	payload_sz = FILECACHE_MTU - sizeof(*eth) - sizeof(*ip) - sizeof(*udp);
	req = (struct filecache_req *)payload;

	// process packet
	switch (req->cmd) {
		case FILECACHE_CMD_READ: {
			read = (struct filecache_read_req *)req;
			((__u32 *)payload)[0] = bpf_filecache_read(read, payload + 4, payload_sz - 4);
			break;
		}
		case FILECACHE_CMD_LOAD: {
			load = (struct filecache_load_req *)req;
			((__u32 *)payload)[0] = bpf_filecache_load(load->key, load->pos, load->len, load->id);
			break;
		}
	}
	
	// adjust packet headers
	adjust_eth_hdr(data);
	adjust_ip_hdr(data, data_end);
	adjust_udp_hdr(data, data_end);

	return XDP_TX;
}

SEC("license") const char __license[] = "Dual BSD/GPL";