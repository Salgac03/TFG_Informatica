#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

// Ruta donde se guardará el mapa
#define MAP_PATH "/sys/fs/bpf/drop_count"

int main() {
    struct bpf_object *obj;
    int prog_fd, map_fd;
    
    // Cargar el programa BPF (suponiendo que se ha compilado en un objeto ELF llamado "xdp_prog.o")
    obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (!obj) {
        perror("Error al abrir el objeto BPF");
        return 1;
    }

    // Cargar los mapas y el programa XDP en el kernel
    if (bpf_object__load(obj)) {
        perror("Error al cargar el programa BPF");
        return 1;
    }

    // Obtener el descriptor del mapa
    map_fd = bpf_object__find_map_fd_by_name(obj, "drop_count");
    if (map_fd < 0) {
        perror("Error al obtener FD del mapa BPF");
        return 1;
    }

    // Vincular el mapa a /sys/fs/bpf/drop_count si no está ya vinculado
    if (bpf_obj_pin(map_fd, MAP_PATH) < 0 && errno != EEXIST) {
        perror("Error al fijar el mapa BPF en /sys/fs/bpf/");
        return 1;
    }

    // Leer valores del mapa
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

    return 0;
}
