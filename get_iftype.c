//
// Created by yudai on 18/05/17.
//

int dev_get_iftype(const char *ifname)
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