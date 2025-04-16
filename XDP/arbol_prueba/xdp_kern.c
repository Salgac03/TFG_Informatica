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
    __uint(max_entries, 2); // Dos valores: uno para XDP_DROP y otro para XDP_PASS
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

// Función para obtener el puerto de origen TCP
static __always_inline __be16 get_src_port(struct iphdr *ip, void *data, void *data_end) {
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(*ip));
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            return tcp->source;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(data + sizeof(*ip));
        if ((void *)udp + sizeof(*udp) <= data_end) {
            return udp->source;
        }
    }
    return 0;
}

// Función para obtener el puerto de destino TCP
static __always_inline __be16 get_dst_port(struct iphdr *ip, void *data, void *data_end) {
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(*ip));
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            return tcp->dest;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(data + sizeof(*ip));
        if ((void *)udp + sizeof(*udp) <= data_end) {
            return udp->dest;
        }
    }
    return 0;
}

SEC("xdp_prog/ransomware_tree")
int ransomware_tree(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int action = XDP_PASS;
    __u32 key = 0; // Clave fija para el contador global

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

        // Obtener puertos src y dst
        __be16 src_port = get_src_port(ip, data, data_end);
        __be16 dst_port = get_dst_port(ip, data, data_end);

                    if (ip_ttl <= 123) {
                if (ip_ttl <= 22) {
                    if (ip_proto <= 60) {
                        if (size <= 61) {
                            action = XDP_DROP; // Clase predicha: 1
                        } else { // size > 61
                            action = XDP_DROP; // Clase predicha: 1
                        }
                    } else { // ip_proto > 60
                        action = XDP_PASS; // Clase predicha: 0
                    }
                } else { // ip_ttl > 22
                    action = XDP_PASS; // Clase predicha: 0
                }
            } else { // ip_ttl > 123
                if (bpf_htons(eth_type) <= 34762) {
                    if (ip_ttl <= 191.50) {
                        if (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP) {
                            action = XDP_DROP; // Clase predicha: 1
                        } else { // src_port > inf
                            action = XDP_DROP; // Clase predicha: 1
                        }
                    } else { // ip_ttl > 191.50
                        if (dst_port <= 2710.50) {
                            action = XDP_DROP; // Clase predicha: 1
                        } else { // dst_port > 2710.50
                            action = XDP_PASS; // Clase predicha: 0
                        }
                    }
                } else { // bpf_htons(eth_type) > 34762
                    action = XDP_PASS; // Clase predicha: 0
                }
            }


    } else if (bpf_htons(eth_type) == ETH_P_IPV6) {
        action = XDP_PASS;
    }
    
    __u32 key_act = (action == XDP_DROP) ? 0 : 1; // 0 para DROP, 1 para PASS
    __u64 *count_ptr = bpf_map_lookup_elem(&packet_count, &key_act);
    if (count_ptr) {
        __sync_fetch_and_add(count_ptr, 1); // Incrementar el contador correspondiente
    }
    return action;
}

char _license[] SEC("license") = "GPL";