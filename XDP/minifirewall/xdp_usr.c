#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>

#define MAP_PATH "/sys/fs/bpf/drop_count"

int main(int argc, char **argv) {
    struct bpf_object *obj;
    int prog_fd, map_fd;
    int ifindex;

    if (argc < 2) {
        fprintf(stderr, "Uso: %s <nombre_de_interfaz>\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        perror("Error al obtener el índice de la interfaz");
        return 1;
    }

    obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (!obj) {
        perror("Error al abrir el objeto BPF");
        return 1;
    }

    if (bpf_object__load(obj)) {
        perror("Error al cargar el programa BPF");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "drop_count");
    if (map_fd < 0) {
        perror("Error al obtener FD del mapa BPF");
        return 1;
    }

    if (bpf_obj_pin(map_fd, MAP_PATH) < 0 && errno != EEXIST) {
        perror("Error al fijar el mapa BPF en /sys/fs/bpf/");
        return 1;
    }

    __u32 key_udp = 0, key_tcp = 1;
    __u64 drop_udp = 0, drop_tcp = 0;

    if (bpf_map_lookup_elem(map_fd, &key_udp, &drop_udp) < 0) {
        perror("Error al leer contador UDP");
        return 1;
    }
    if (bpf_map_lookup_elem(map_fd, &key_tcp, &drop_tcp) < 0) {
        perror("Error al leer contador TCP");
        return 1;
    }

    printf("Paquetes UDP descartados: %llu\n", drop_udp);
    printf("Paquetes TCP descartados: %llu\n", drop_tcp);

    // Obtener el descriptor del programa XDP
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_filter"));
    if (prog_fd < 0) {
        perror("Error al obtener FD del programa BPF");
        return 1;
    }

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
        perror("Error al adjuntar el programa BPF a la interfaz");
        return 1;
    }

    return 0;
}
