/*
 * XDP Multicast Forwarder - Userspace Loader
 *
 * This program loads the XDP program and configures:
 *   - Global variables (g_new_src, g_new_dst) for packet rewriting
 *   - DEVMAP (tx_port) for output interface redirection
 */

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct rewrite_dst {
  __u32 addr;
  __u16 port;
  __u16 ifindex;
  __u8 mac[6];
};

struct rewrite_src {
  __u32 addr;
  __u16 port;
  __u16 ifindex;
  __u8 mac[6];
};

static int parse_mac(const char *mac_str, __u8 *mac) {
  return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1],
                &mac[2], &mac[3], &mac[4], &mac[5]) == 6
             ? 0
             : -1;
}

static void usage(const char *prog) {
  fprintf(
      stderr,
      "Usage: %s <ifname_in> <ifname_out> <src_ip> <src_port> <src_mac> "
      "<dst_ip> <dst_port> <dst_mac>\n"
      "\n"
      "Arguments:\n"
      "  ifname_in   Input interface\n"
      "  ifname_out  Output interface\n"
      "  src_ip      New source IP address\n"
      "  src_port    New source port\n"
      "  src_mac     New source MAC address (format: xx:xx:xx:xx:xx:xx)\n"
      "  dst_ip      New destination IP address\n"
      "  dst_port    New destination port\n"
      "  dst_mac     New destination MAC address (format: xx:xx:xx:xx:xx:xx)\n"
      "\n"
      "Example:\n"
      "  %s eth0 eth1 192.168.1.100 5000 aa:bb:cc:dd:ee:ff 10.0.0.1 6000 "
      "11:22:33:44:55:66\n",
      prog, prog);
}

int main(int argc, char **argv) {
  struct bpf_object *obj;
  struct bpf_program *prog;
  struct bpf_map *data_map, *tx_port_map;
  int prog_fd, data_fd, tx_port_fd;
  int ifindex_in, ifindex_out;
  struct rewrite_src src = {0};
  struct rewrite_dst dst = {0};
  __u32 key = 0;
  int err;

  if (argc != 9) {
    usage(argv[0]);
    return 1;
  }

  ifindex_in = if_nametoindex(argv[1]);
  if (!ifindex_in) {
    fprintf(stderr, "Error: Invalid input interface %s\n", argv[1]);
    return 1;
  }

  ifindex_out = if_nametoindex(argv[2]);
  if (!ifindex_out) {
    fprintf(stderr, "Error: Invalid output interface %s\n", argv[2]);
    return 1;
  }

  src.addr = inet_addr(argv[3]);
  src.port = htons(atoi(argv[4]));
  src.ifindex = ifindex_in;
  if (parse_mac(argv[5], src.mac) < 0) {
    fprintf(stderr, "Error: Invalid source MAC address %s\n", argv[5]);
    return 1;
  }

  dst.addr = inet_addr(argv[6]);
  dst.port = htons(atoi(argv[7]));
  dst.ifindex = ifindex_out;
  if (parse_mac(argv[8], dst.mac) < 0) {
    fprintf(stderr, "Error: Invalid destination MAC address %s\n", argv[8]);
    return 1;
  }

  obj = bpf_object__open_file("xdp_forwarder.o", NULL);
  if (libbpf_get_error(obj)) {
    fprintf(stderr, "Error: Failed to open BPF object\n");
    return 1;
  }

  if (bpf_object__load(obj)) {
    fprintf(stderr, "Error: Failed to load BPF object\n");
    goto cleanup;
  }

  prog = bpf_object__find_program_by_name(obj, "xdp_multicast_forwarder");
  if (!prog) {
    fprintf(stderr, "Error: Failed to find XDP program\n");
    goto cleanup;
  }
  prog_fd = bpf_program__fd(prog);

  data_map = bpf_object__find_map_by_name(obj, ".data");
  if (!data_map) {
    fprintf(stderr, "Error: Failed to find .data map\n");
    goto cleanup;
  }
  data_fd = bpf_map__fd(data_map);

  struct {
    struct rewrite_dst dst;
    struct rewrite_src src;
  } data_section;

  memcpy(&data_section.dst, &dst, sizeof(dst));
  memcpy(&data_section.src, &src, sizeof(src));

  if (bpf_map_update_elem(data_fd, &key, &data_section, BPF_ANY)) {
    fprintf(stderr, "Error: Failed to update global variables\n");
    goto cleanup;
  }

  tx_port_map = bpf_object__find_map_by_name(obj, "tx_port");
  if (!tx_port_map) {
    fprintf(stderr, "Error: Failed to find tx_port map\n");
    goto cleanup;
  }
  tx_port_fd = bpf_map__fd(tx_port_map);

  if (bpf_map_update_elem(tx_port_fd, &key, &ifindex_out, BPF_ANY)) {
    fprintf(stderr, "Error: Failed to configure DEVMAP\n");
    goto cleanup;
  }

  err = bpf_xdp_attach(ifindex_in, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
  if (err) {
    fprintf(stderr, "Error: Failed to attach XDP program to %s (err=%d)\n",
            argv[1], err);
    goto cleanup;
  }

  printf("XDP Multicast Forwarder loaded successfully!\n");
  printf("  Input interface:  %s (ifindex %d)\n", argv[1], ifindex_in);
  printf("  Output interface: %s (ifindex %d)\n", argv[2], ifindex_out);
  printf("  Source rewrite:   %s:%d (%s)\n", argv[3], atoi(argv[4]), argv[5]);
  printf("  Dest rewrite:     %s:%d (%s)\n", argv[6], atoi(argv[7]), argv[8]);
  printf("\nPress Ctrl+C to detach and exit...\n");

  pause();

  bpf_xdp_detach(ifindex_in, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
  printf("\nXDP program detached.\n");

cleanup:
  bpf_object__close(obj);
  return 0;
}
