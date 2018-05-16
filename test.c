/*
 * filter2xdp - compile and load PCAP filter expression as XDP BPF program.
 *
 * Copyright (C) 2017 Tobias Klauser
 * Subject to the GPL, version 2.
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/filter.h>

#include "bpf_load.h"
#include "cbpf.h"
#include "ebpf.h"
#include "pcap_helpers.h"
#include "utils.h"

void filter_try_compile(const char *str, struct sock_fprog *cbpf, int link_type);
int bpf_convert_filter(struct sock_filter *prog, size_t len, struct bpf_insn *new_prog, size_t *new_len, bool invert);

static int dev_get_iftype(const char *ifname)
{
	int ret, sock, type;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		panic("Cannot create AF_INET socket: %s\n", strerror(errno));

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	ret = ioctl(sock, SIOCGIFHWADDR, &ifr);
	if (unlikely(ret))
		panic("Cannot get iftype for device %s\n", ifname);

	type = ifr.ifr_hwaddr.sa_family;
	close(sock);

	return type;
}

static int dev_get_ifindex(const char *ifname)
{
	int ret, sock, index;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		panic("Cannot create AF_INET socket: %s\n", strerror(errno));

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	ret = ioctl(sock, SIOCGIFINDEX, &ifr);
	if (unlikely(ret))
		panic("Cannot get ifindex for device %s\n", ifname);

	index = ifr.ifr_ifindex;
	close(sock);

	return index;
}

int main(void)
{
	int ret, ifindex, fd;
	bool invert = false, raw = false;
	const char *ifname = "wlp3s0";
	const char *filter = NULL;
	struct sock_fprog cbpf;
	struct bpf_insn *ebpf;
	size_t ebpf_len = 0;

	filter = "tcp and port 80";
	ifindex = dev_get_ifindex(ifname);

	printf("PCAP filter string: %s\n", filter);

	memset(&cbpf, 0, sizeof(cbpf));
	filter_try_compile(filter, &cbpf, dev_get_iftype(ifname));

	printf("cBPF program (%u insns):\n", cbpf.len);
	cbpf_dump_all(&cbpf, raw);

	/* 1st pass: calculate the eBPF program length */
	ret = bpf_convert_filter(cbpf.filter, cbpf.len, NULL, &ebpf_len, invert);
	if (ret < 0)
		panic("Cannot get eBPF length\n");

	ebpf = xmalloc(ebpf_len * sizeof(*ebpf));

	/* 2nd pass: remap cBPF insns into eBPF insns */
	ret = bpf_convert_filter(cbpf.filter, cbpf.len, ebpf, &ebpf_len, invert);
	if (ret < 0)
		panic("Cannot convert cBPF to eBPF\n");

	printf("eBPF program (%zu insns):\n", ebpf_len);
	ebpf_dump_all(ebpf, ebpf_len, raw);


	fd = bpf_load_and_attach_xdp(ebpf, ebpf_len);
	if (fd < 0)
		panic("Cannot load and attach eBPF program\n");

	ret = set_link_xdp_fd(ifindex, fd);
	if (ret < 0)
		panic("Cannot set XDP eBPF program on interface %s\n", ifname);

	while (true) {
		sleep(1);
	}

	return 0;
}
