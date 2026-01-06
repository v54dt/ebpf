/*
 * XDP Multicast Forwarder
 *
 * Description:
 *   Intercepts specific multicast UDP packets from NIC A, rewrites
 *   the packet headers (Ethernet, IP, UDP), and redirects to NIC B
 *   for transmission to the final destination (NIC C).
 */

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_UDP_LENGTH 1500
#define ETH_P_IP 0x0800

#define MCAST_IP_1 0xE0006464 /* 224.0.100.100 */
#define MCAST_PORT_1 10000
#define MCAST_IP_2 0xE0026464 /* 224.2.100.100 */
#define MCAST_PORT_2 10002

/* Multicast range: 224.0.0.0/4 */
#define MCAST_RANGE_MASK 0xF0000000
#define MCAST_RANGE_PREFIX 0xE0000000

char _license[] SEC("license") = "GPL";

#pragma pack(push, 1)
struct rewrite_dst {
  __u32 addr;
  __u16 port;
  __u16 ifindex;
  __u8 mac[6];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct rewrite_src {
  __u32 addr;
  __u16 port;
  __u16 ifindex;
  __u8 mac[6];
};
#pragma pack(pop)

struct rewrite_dst g_new_dst = {0};
struct rewrite_src g_new_src = {0};

struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 1);
} tx_port SEC(".maps");

static __always_inline __u16 compute_ip_checksum(unsigned short *buf,
                                                 int bufsz) {
  unsigned long sum = 0;

  while (bufsz > 1) {
    sum += *buf;
    buf++;
    bufsz -= 2;
  }

  if (bufsz == 1) {
    sum += *(unsigned char *)buf;
  }

  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}

static __always_inline __u16 compute_udp_checksum(struct iphdr *iph,
                                                  struct udphdr *udp,
                                                  void *data_end) {
  __u32 csum = 0;
  __u16 *buf = (__u16 *)udp;

  csum += iph->saddr & 0xFFFF;
  csum += (iph->saddr >> 16) & 0xFFFF;
  csum += iph->daddr & 0xFFFF;
  csum += (iph->daddr >> 16) & 0xFFFF;
  csum += bpf_htons((__u16)iph->protocol);
  csum += udp->len;

  for (int i = 0; i < MAX_UDP_LENGTH; i += 2) {
    if ((void *)(buf + 1) > data_end)
      break;
    csum += *buf;
    buf++;
  }

  if ((void *)buf < data_end)
    csum += ((*(__u8 *)buf) << 8);

  csum = (csum & 0xFFFF) + (csum >> 16);
  csum = (csum & 0xFFFF) + (csum >> 16);
  return ~(__u16)csum;
}

SEC("xdp")
int xdp_multicast_forwarder(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth;
  struct iphdr *iph;
  struct udphdr *udp;
  __u32 orig_daddr;
  __u16 orig_dport;

  eth = data;
  if ((void *)eth + sizeof(*eth) > data_end)
    return XDP_PASS;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return XDP_PASS;

  iph = data + sizeof(*eth);
  if ((void *)iph + sizeof(*iph) > data_end)
    return XDP_PASS;

  /* Validate IP header length is at least 5 */
  if (iph->ihl < 5)
    return XDP_PASS;

  /* Calculate actual IP header size */
  __u32 ip_hdr_len = iph->ihl * 4;

  /* Ensure full IP header is within packet bounds */
  if ((void *)iph + ip_hdr_len > data_end)
    return XDP_PASS;

  if (iph->protocol != IPPROTO_UDP)
    return XDP_PASS;

  /* Calculate UDP header position using actual IP header length */
  udp = (struct udphdr *)((void *)iph + ip_hdr_len);
  if ((void *)udp + sizeof(*udp) > data_end)
    return XDP_PASS;

  orig_daddr = bpf_ntohl(iph->daddr);
  orig_dport = bpf_ntohs(udp->dest);

  if ((orig_daddr & MCAST_RANGE_MASK) != MCAST_RANGE_PREFIX)
    return XDP_PASS;

  if (!((orig_daddr == MCAST_IP_1 && orig_dport == MCAST_PORT_1) ||
        (orig_daddr == MCAST_IP_2 && orig_dport == MCAST_PORT_2)))
    return XDP_PASS;

  __builtin_memcpy(eth->h_source, g_new_src.mac, 6);
  __builtin_memcpy(eth->h_dest, g_new_dst.mac, 6);
  iph->saddr = g_new_src.addr;
  iph->daddr = g_new_dst.addr;
  udp->source = g_new_src.port;
  udp->dest = g_new_dst.port;

  iph->check = 0;
  iph->check = compute_ip_checksum((unsigned short *)iph, ip_hdr_len);
  udp->check = 0;
  udp->check = compute_udp_checksum(iph, udp, data_end);

  return bpf_redirect_map(&tx_port, 0, 0);
}
