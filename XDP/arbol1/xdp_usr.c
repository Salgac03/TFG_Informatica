#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>

#define MAP_PATH "/sys/fs/bpf/packet_count"

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

    map_fd = bpf_object__find_map_fd_by_name(obj, "packet_count");
    if (map_fd < 0) {
        perror("Error al obtener FD del mapa BPF");
        return 1;
    }

    if (bpf_obj_pin(map_fd, MAP_PATH) < 0 && errno != EEXIST) {
        perror("Error al fijar el mapa BPF en /sys/fs/bpf/");
        return 1;
    }

    // Obtener el descriptor del programa XDP
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "ransomware_tree"));
    if (prog_fd < 0) {
        perror("Error al obtener FD del programa BPF");
        return 1;
    }

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
        perror("Error al adjuntar el programa BPF a la interfaz");
        return 1;
    }

    printf("Programa XDP adjuntado a la interfaz %s\n", argv[1]);
    printf("Monitorizando contadores de paquetes (Ctrl+C para salir)...\n");

    while (1) {
        __u32 drop_key = 0; // Clave para XDP_DROP
        __u32 pass_key = 1; // Clave para XDP_PASS
        __u64 drop_count = 0, pass_count = 0;

        if (bpf_map_lookup_elem(map_fd, &drop_key, &drop_count) < 0) {
            perror("Error al leer contador de paquetes descartados");
        }
        if (bpf_map_lookup_elem(map_fd, &pass_key, &pass_count) < 0) {
            perror("Error al leer contador de paquetes pasados");
        }

        printf("\nTotal de paquetes descartados (XDP_DROP): %llu\n", drop_count);
        printf("Total de paquetes pasados (XDP_PASS): %llu\n", pass_count);

        sleep(1); // Esperar 1 segundo antes de volver a leer
    }

    return 0;
}
