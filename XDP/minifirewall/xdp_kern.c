#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// Mapa BPF para contar paquetes descartados
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);   // Tipo de mapa: array
    __uint(max_entries, 2);             // Máximo de 2 entradas (una para UDP y otra para TCP)
    __type(key, __u32);                 // Clave: índice en el array (0 = UDP, 1 = TCP)
    __type(value, __u64);               // Valor: contador de paquetes descartados
} drop_count SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Verificación de cabecera Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Verificar si el paquete es IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    __u32 key;
    __u64 *count;

    // Filtrado de paquetes UDP
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;

        if (udp->dest == __constant_htons(53))  // Solo permitir destino 53 (DNS)
            return XDP_PASS;
        else {
            key = 0;  // Índice 0 para UDP
            count = bpf_map_lookup_elem(&drop_count, &key);
            if (count)
                __sync_fetch_and_add(count, 1);  // Incrementar contador de descartados
            return XDP_DROP;
        }
    }

    // Filtrado de paquetes TCP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        if (tcp->source == __constant_htons(80)) {  // Bloquear paquetes desde el puerto 80 (HTTP)
            key = 1;  // Índice 1 para TCP
            count = bpf_map_lookup_elem(&drop_count, &key);
            if (count)
                __sync_fetch_and_add(count, 1);  // Incrementar contador de descartados
            return XDP_DROP;
        }
        else
            return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
