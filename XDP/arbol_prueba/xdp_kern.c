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

// Función para obtener el valor de TTL (Time to Live)
static __always_inline __u8 get_ip_ttl(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return 0;
    if (bpf_htons(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) > data_end)
            return 0;
        return ip->ttl;
    }
    return 0;
}

// Función para obtener el tamaño total del paquete IP
static __always_inline __u16 get_ip_tot_len(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return 0;
    if (bpf_htons(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) > data_end)
            return 0;
        return bpf_ntohs(ip->tot_len);
    }
    return 0;
}

// Función para obtener el identificador del paquete IP
static __always_inline __u16 get_ip_id(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return 0;
    if (bpf_htons(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) > data_end)
            return 0;
        return bpf_ntohs(ip->id);
    }
    return 0;
}

// Función para obtener los flags de fragmentación IP
static __always_inline __u8 get_ip_frag_flags(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return 0;
    if (bpf_htons(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) > data_end)
            return 0;
        return ip->frag_off >> 13; // Los 3 bits superiores
    }
    return 0;
}

// Función para obtener el offset de fragmento IP
static __always_inline __u16 get_ip_frag_offset(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return 0;
    if (bpf_htons(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) > data_end)
            return 0;
        return bpf_ntohs(ip->frag_off & 0x1FFF);
    }
    return 0;
}

// Función para obtener el puerto de origen TCP/UDP (ahora sin recibir la estructura ip)
static __always_inline __be16 get_src_port(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return 0;
    if (bpf_htons(eth->h_proto) != ETH_P_IP)
        return 0;
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(*eth) + sizeof(*ip));
        if ((void *)tcp + sizeof(*tcp) <= data_end)
            return tcp->source;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
        if ((void *)udp + sizeof(*udp) <= data_end)
            return udp->source;
    }
    return 0;
}

// Función para obtener el puerto de destino TCP/UDP (ahora sin recibir la estructura ip)
static __always_inline __be16 get_dst_port(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return 0;
    if (bpf_htons(eth->h_proto) != ETH_P_IP)
        return 0;
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(*eth) + sizeof(*ip));
        if ((void *)tcp + sizeof(*tcp) <= data_end)
            return tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
        if ((void *)udp + sizeof(*udp) <= data_end)
            return udp->dest;
    }
    return 0;
}

SEC("xdp_prog/ransomware_tree")
int ransomware_tree(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int action = XDP_PASS; // Acción por defecto

    // Verificar límites del encabezado Ethernet
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    __be16 eth_type = eth->h_proto;

    // Si es IPv6, no se procesa (se podría ampliar si fuera necesario)
    if (bpf_htons(eth_type) == ETH_P_IPV6) {
        action = XDP_PASS;
    }

    // Extraer datos de la capa IP (ya no se necesita pasar la estructura ip a las funciones de puertos)
    __u8 ip_proto = 0;
    {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end)
            ip_proto = ip->protocol;
    }
    __u8 ip_ttl         = get_ip_ttl(data, data_end);
    __u16 ip_tot_len    = get_ip_tot_len(data, data_end);
    __u16 ip_id         = get_ip_id(data, data_end);
    __u8 ip_frag_flags  = get_ip_frag_flags(data, data_end);
    __u16 ip_frag_offset= get_ip_frag_offset(data, data_end);

    // Obtener puertos src y dst usando las nuevas funciones
    __be16 src_port = get_src_port(data, data_end);
    __be16 dst_port = get_dst_port(data, data_end);

                if (ip_ttl <= 123 && ip_ttl != 0) {
                if (ip_ttl <= 22 && ip_ttl != 0) {
                    if (ip_id <= 34375) {
                        if (ip_frag_flags != 2) {
                            action = XDP_DROP; // Clase predicha: 1
                        } else { // ip_frag_flags_DF > 0.50
                            action = XDP_PASS; // Clase predicha: 0
                        }
                    } else { // ip_id > 34375
                        action = XDP_PASS; // Clase predicha: 0
                    }
                } else { // ip_ttl > 22
                    action = XDP_PASS; // Clase predicha: 0
                }
            } else { // ip_ttl > 123
                if (bpf_htons(eth_type) <= 34762) {
                    if (ip_ttl <= 191.50 && ip_ttl != 0) {
                        if (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP) {
                            action = XDP_DROP; // Clase predicha: 1
                        } else { // dst_port > inf
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

    
    __u32 key_act = (action == XDP_DROP) ? 0 : 1; // 0 para DROP, 1 para PASS
    __u64 *count_ptr = bpf_map_lookup_elem(&packet_count, &key_act);
    if (count_ptr) {
        __sync_fetch_and_add(count_ptr, 1); // Incrementar el contador correspondiente
    }
    return action;
}

char _license[] SEC("license") = "GPL";