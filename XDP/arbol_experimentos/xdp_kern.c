#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// ---------- Funciones auxiliares headers ----------
static __always_inline struct iphdr *get_ip_header(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return NULL;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return NULL;
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return NULL;
    return ip;
}

static __always_inline struct tcphdr *get_tcp_header(void *data, void *data_end)
{
    struct iphdr *ip = get_ip_header(data, data_end);
    if (!ip || ip->protocol != IPPROTO_TCP)
        return NULL;
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return NULL;
    return tcp;
}

static __always_inline __be16 get_src_port(void *data, void *data_end)
{
    struct iphdr *ip = get_ip_header(data, data_end);
    if (!ip)
        return 0;
    void *l4 = (void *)ip + ip->ihl * 4;
    if (ip->protocol == IPPROTO_TCP && l4 + sizeof(struct tcphdr) <= data_end)
        return ((struct tcphdr *)l4)->source;
    if (ip->protocol == IPPROTO_UDP && l4 + sizeof(struct udphdr) <= data_end)
        return ((struct udphdr *)l4)->source;
    return 0;
}

static __always_inline __be16 get_dst_port(void *data, void *data_end)
{
    struct iphdr *ip = get_ip_header(data, data_end);
    if (!ip)
        return 0;
    void *l4 = (void *)ip + ip->ihl * 4;
    if (ip->protocol == IPPROTO_TCP && l4 + sizeof(struct tcphdr) <= data_end)
        return ((struct tcphdr *)l4)->dest;
    if (ip->protocol == IPPROTO_UDP && l4 + sizeof(struct udphdr) <= data_end)
        return ((struct udphdr *)l4)->dest;
    return 0;
}

// ---------- Funciones auxiliares IP ----------
static __always_inline __u8 get_ip_ttl(void *data, void *data_end)
{
    struct iphdr *ip = get_ip_header(data, data_end);
    return ip ? ip->ttl : 0;
}

static __always_inline __u16 get_ip_tot_len(void *data, void *data_end)
{
    struct iphdr *ip = get_ip_header(data, data_end);
    return ip ? bpf_ntohs(ip->tot_len) : 0;
}

static __always_inline __u16 get_ip_id(void *data, void *data_end)
{
    struct iphdr *ip = get_ip_header(data, data_end);
    return ip ? bpf_ntohs(ip->id) : 0;
}

static __always_inline __u8 get_ip_frag_flags(void *data, void *data_end)
{
    struct iphdr *ip = get_ip_header(data, data_end);
    return ip ? ip->frag_off >> 13 : 0;
}

static __always_inline __u16 get_ip_frag_offset(void *data, void *data_end)
{
    struct iphdr *ip = get_ip_header(data, data_end);
    return ip ? bpf_ntohs(ip->frag_off & 0x1FFF) : 0;
}

// ---------- Programa principal ----------
SEC("xdp")
int ransomware_tree(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int action = XDP_PASS;

    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6)
        action = XDP_PASS;

    // Variables IP
    __u8 ip_ttl = get_ip_ttl(data, data_end);
    __u16 ip_tot_len = get_ip_tot_len(data, data_end);
    __u16 ip_id = get_ip_id(data, data_end);
    __u8 ip_frag_flags = get_ip_frag_flags(data, data_end);
    __u16 ip_frag_offset = get_ip_frag_offset(data, data_end);

    // Variables TCP
    struct tcphdr *tcp = get_tcp_header(data, data_end);
    __u32 tcp_ack = tcp ? bpf_ntohl(tcp->ack_seq) : 0;
    __u32 tcp_seq = tcp ? bpf_ntohl(tcp->seq) : 0;
    __u16 tcp_window = tcp ? bpf_ntohs(tcp->window) : 0;
	__u32 size = (void *)(long)ctx->data_end - (void *)(long)ctx->data;

    // Puertos
    __be16 src_port = tcp ? tcp->source : get_src_port(data, data_end);
    __be16 dst_port = tcp ? tcp->dest : get_dst_port(data, data_end);

                if (tcp_ack <= 2853857664) {
                if (tcp_seq <= 2853857664) {
                    if (ip_id <= 32768) {
                        if (src_port <= 444) {
                            action = XDP_PASS; // Clase predicha: 0
                        } else { // src_port > 444
                            action = XDP_DROP; // Clase predicha: 1
                        }
                    } else { // ip_id > 32768
                        if (ip_frag_flags != 2) {
                            action = XDP_PASS; // Clase predicha: 0
                        } else { // ip_frag_flags_DF > 0.50
                            action = XDP_PASS; // Clase predicha: 0
                        }
                    }
                } else { // tcp_seq > 2853857664
                    if (tcp_window <= 265.50) {
                        if (src_port <= 1656) {
                            action = XDP_PASS; // Clase predicha: 0
                        } else { // src_port > 1656
                            action = XDP_DROP; // Clase predicha: 1
                        }
                    } else { // tcp_window > 265.50
                        if (ip_tot_len != 0) {
                            action = XDP_PASS; // Clase predicha: 0
                        } else { // ip_tot_len > inf
                            action = XDP_DROP; // Clase predicha: 1
                        }
                    }
                }
            } else { // tcp_ack > 2853857664
                if (ip_tot_len != 0) {
                    if (tcp_window <= 264.50) {
                        if (src_port <= 1656) {
                            action = XDP_PASS; // Clase predicha: 0
                        } else { // src_port > 1656
                            action = XDP_DROP; // Clase predicha: 1
                        }
                    } else { // tcp_window > 264.50
                        if (size <= 57) {
                            action = XDP_PASS; // Clase predicha: 0
                        } else { // size > 57
                            action = XDP_PASS; // Clase predicha: 0
                        }
                    }
                } else { // ip_tot_len > inf
                    action = XDP_DROP; // Clase predicha: 1
                }
            }


	if ( action != XDP_DROP)
		action = XDP_PASS;

    return action;
}

char _license[] SEC("license") = "GPL";
