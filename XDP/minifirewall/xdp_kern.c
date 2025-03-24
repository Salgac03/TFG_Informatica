#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>

// Mapa para contar los paquetes descartados
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);  // Tipo de mapa
    __uint(max_entries, 2);            // Máximo de 2 entradas
    __type(key, __u32);                // Clave
    __type(value, __u64);              // Valor
} drop_count SEC(".maps");

// Función XDP que filtra los paquetes
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Verificar si el paquete está dentro del límite de datos
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;  // Si no hay datos suficientes, descartar

    // Verificación de cabecera Ethernet
    struct ethhdr *eth = data;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;  // Si no es IP, permitir el paquete

    // Verificar la cabecera IP
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Contador para UDP
    __u32 key = 0;  // 0 para UDP
    __u64 *count;

    // Filtrado de paquetes UDP
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;

        if (udp->dest == __constant_htons(53))  // Solo permitir DNS
            return XDP_PASS;
        else {
            // Incrementar contador de paquetes descartados
            count = bpf_map_lookup_elem(&drop_count, &key);
            if (count)
                __sync_fetch_and_add(count, 1);
            return XDP_DROP;
        }
    }

    // Filtrado de paquetes TCP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        if (tcp->source == __constant_htons(80)) {  // Bloquear paquetes HTTP
            key = 1;  // 1 para TCP
            count = bpf_map_lookup_elem(&drop_count, &key);
            if (count)
                __sync_fetch_and_add(count, 1);  // Incrementar contador
            return XDP_DROP;
        }
        else
            return XDP_PASS;
    }

    return XDP_PASS;  // Si no se cumplen las condiciones, pasar el paquete
}

// Licencia del módulo
char _license[] SEC("license") = "GPL";

