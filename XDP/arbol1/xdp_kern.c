#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Definición del mapa usando la sintaxis recomendada
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} drop_count SEC("maps"); // Tamaño 2 para UDP (key 0) y TCP (key 1)

SEC("xdp_prog/ransomware_tree")
int ransomware_tree(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int action = XDP_PASS;
    __u32 key = -1; // Inicializar con un valor inválido

    // Verificar límites del encabezado Ethernet
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    __be16 eth_type = eth->h_proto;

    // Manejar IPv4
    if (bpf_htons(eth_type) == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) > data_end)
            return XDP_PASS;

        __u8 ip_proto = ip->protocol;
        __u8 ip_ttl = ip->ttl;
        __u16 size = bpf_htons(ip->tot_len);

        if (ip_ttl <= 123) {
            if (ip_ttl <= 22) {
                if (ip_proto <= 60) {
                    action = XDP_DROP;
                } else {
                    action = XDP_DROP;
                }
            } else {
                action = XDP_PASS;
            }
        } else { // ip_ttl > 123
            if (bpf_htons(eth_type) <= 34762) { // eth_type <= 0x874A
                if (ip_ttl <= 191) {
                    // src_port <= inf: Asumir que es TCP o UDP (tiene puerto fuente)
                    if (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP) {
                        action = XDP_DROP;
                    }
                    // src_port > inf: Asumir que no es TCP o UDP (sin puerto fuente)
                    else {
                        action = XDP_DROP;
                    }
                } else { // ip_ttl > 191
                    if (ip_proto == IPPROTO_TCP) {
                        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
                        if ((void *)tcp + sizeof(*tcp) <= data_end) {
                            __be16 dst_port = tcp->dest;
                            if (bpf_htons(dst_port) <= 2710) {
                                action = XDP_DROP;
                            } else {
                                action = XDP_PASS;
                            }
                        }
                    } else if (ip_proto == IPPROTO_UDP) {
                        struct udphdr *udp = (void *)ip + sizeof(*ip);
                        if ((void *)udp + sizeof(*udp) <= data_end) {
                            __be16 dst_port = udp->dest;
                            if (bpf_htons(dst_port) <= 2710) {
                                action = XDP_DROP;
                            } else {
                                action = XDP_PASS;
                            }
                        }
                    } else {
                        action = XDP_PASS;
                    }
                }
            } else { // eth_type > 34762
                action = XDP_PASS;
            }
        }

        // Actualizar el contador de caídas en el mapa
        if (action == XDP_DROP) {
            if (ip_proto == IPPROTO_UDP) {
                key = 0;
            } else if (ip_proto == IPPROTO_TCP) {
                key = 1;
            }
            if (key != -1) {
                __u64 *drop_count_ptr = bpf_map_lookup_elem(&drop_count, &key);
                if (drop_count_ptr) {
                    (*drop_count_ptr)++;
                }
            }
        }
    } else if (bpf_htons(eth_type) == ETH_P_IPV6) {
        action = XDP_PASS;
    }

    return action;
}

char _license[] SEC("license") = "GPL";
