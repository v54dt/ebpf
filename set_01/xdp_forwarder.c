#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_UDP_LENGTH 1500
#define ETH_P_IP 0x0800

char __license[] SEC("license") = "MIT";

#pragma pack(push, 1)
struct dst_info {
  __u32 addr;
  __u16 port;
  __u16 ifindex;
  __u8 mac[6];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct src_info {
  __u32 addr;
  __u16 port;
  __u16 ifindex;
  __u8 mac[6];
};
#pragma pack(pop)

struct dst_info g_dst = {0};
struct src_info g_src = {0};

static __always_inline __u16 ip_checksum(unsigned short *buf, int bufsz) {
  unsigned long sum = 0;

  while (bufsz > 1) {
    sum += *buf;
    buf++;
    bufsz -= 2;
  }

  if (bufsz == 1) {
    sum += *(unsigned char *)buf;
  }

  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}

static __always_inline __u16 udp_checksum(struct iphdr *ip, struct udphdr *udp,
                                          void *data_end) {
  __u32 csum = 0;
  __u16 *buf = (__u16 *)udp;

  csum += ip->saddr & 0xFFFF;
  csum += (ip->saddr >> 16) & 0xFFFF;

  csum += ip->daddr & 0xFFFF;
  csum += (ip->daddr >> 16) & 0xFFFF;

  csum += bpf_htons((__u16)ip->protocol);

  csum += udp->len;

  for (int i = 0; i < MAX_UDP_LENGTH; i += 2) {
    if ((void *)(buf + 1) > data_end) {
      break;
    }
    csum += *buf;
    buf++;
  }

  if ((void *)buf + 1 <= data_end) {
    csum += ((*(__u8 *)buf) << 8);
  }

  csum = (csum & 0xFFFF) + (csum >> 16);
  csum = (csum & 0xFFFF) + (csum >> 16);

  return ~(__u16)csum;
}

SEC("xdp") int forward_multicast_packet(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(*eth) > data_end)
    return XDP_PASS;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return XDP_PASS;

  struct iphdr *iph = data + sizeof(*eth);
  if ((void *)iph + sizeof(*iph) > data_end)
    return XDP_PASS;

  if (iph->protocol != IPPROTO_UDP)
    return XDP_PASS;

  struct udphdr *udp;
  udp = data + sizeof(*eth) + sizeof(*iph);

  if ((void *)udp + sizeof(*udp) > data_end)
    return XDP_PASS;

  __u32 orig_daddr = bpf_ntohl(iph->daddr);
  __u16 orig_dport = bpf_ntohs(udp->dest);

  // Multicast range check: 224.0.0.0/4 (0xE0000000)
  if ((orig_daddr & 0xF0000000) != 0xE0000000) {
    return XDP_PASS;
  }

  // Check against allowed multicast destinations:
  // - 224.0.100.100:10000 (0xE0006464)
  // - 224.2.100.100:10002 (0xE0026464)
  if (!((orig_daddr == 0xE0006464 && orig_dport == 10000) ||
        (orig_daddr == 0xE0026464 && orig_dport == 10002))) {
    return XDP_PASS;
  }

  __builtin_memcpy(eth->h_source, g_src.mac, 6);
  __builtin_memcpy(eth->h_dest, g_dst.mac, 6);

  iph->saddr = g_src.addr;
  iph->daddr = g_dst.addr;

  udp->source = g_src.port;
  udp->dest = g_dst.port;

  iph->check = 0;
  iph->check = ip_checksum((unsigned short *)iph, sizeof(*iph));

  udp->check = 0;
  udp->check = udp_checksum(iph, udp, data_end);

  return XDP_TX;
}