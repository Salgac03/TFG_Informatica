#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>

#define MAP_PATH "/sys/fs/bpf/packet_count"

static volatile sig_atomic_t stop;

static void handle_sigint(int sig)
{
    (void)sig;
    stop = 1;
}

/* Compat: usa la API XDP que exista en la libbpf del sistema */
static int xdp_set_link_fd_compat(int ifindex, int prog_fd, __u32 flags)
{
    void *handle = NULL;
    void *sym = NULL;

    /* Intentar cargar libbpf explícitamente (evita RTLD_DEFAULT) */
    handle = dlopen("libbpf.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        handle = dlopen("libbpf.so", RTLD_NOW | RTLD_LOCAL);
    }
    if (!handle) {
        /* Si no se puede abrir, devolvemos error */
        return -ENOSYS;
    }

    /* 1) API antigua */
    sym = dlsym(handle, "bpf_set_link_xdp_fd");
    if (sym) {
        int (*fn)(int, int, __u32) = (int (*)(int, int, __u32))sym;
        int ret = fn(ifindex, prog_fd, flags);
        dlclose(handle);
        return ret;
    }

    /* 2) API más nueva (opts) */
    sym = dlsym(handle, "bpf_set_link_xdp_fd_opts");
    if (sym) {
        int (*fn)(int, int, __u32, const void *) =
            (int (*)(int, int, __u32, const void *))sym;
        int ret = fn(ifindex, prog_fd, flags, NULL);
        dlclose(handle);
        return ret;
    }

    dlclose(handle);
    return -ENOSYS;
}

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

    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "ransomware_tree"));
    if (prog_fd < 0) {
        perror("Error al obtener FD del programa BPF");
        return 1;
    }

    int err = xdp_set_link_fd_compat(ifindex, prog_fd, 0);
    if (err < 0) {
        if (err == -ENOSYS) {
            fprintf(stderr,
                    "Error: no se pudo localizar en libbpf ninguna API XDP (bpf_set_link_xdp_fd / _opts).\n"
                    "Solución recomendada: enlazar/instalar libbpf completa o usar libxdp (xdp-tools).\n");
        } else {
            perror("Error al adjuntar el programa BPF a la interfaz");
        }
        return 1;
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    printf("Programa XDP adjuntado a la interfaz %s\n", argv[1]);
    printf("Monitorizando contadores de paquetes (Ctrl+C para salir)...\n");

    while (!stop) {
        __u32 drop_key = 0;
        __u32 pass_key = 1;
        __u64 drop_count = 0, pass_count = 0;

        if (bpf_map_lookup_elem(map_fd, &drop_key, &drop_count) < 0) {
            perror("Error al leer contador de paquetes descartados");
        }
        if (bpf_map_lookup_elem(map_fd, &pass_key, &pass_count) < 0) {
            perror("Error al leer contador de paquetes pasados");
        }

        printf("\nTotal de paquetes descartados (XDP_DROP): %llu\n",
               (unsigned long long)drop_count);
        printf("Total de paquetes pasados (XDP_PASS): %llu\n",
               (unsigned long long)pass_count);

        sleep(1);
    }

    /* Detach (fd = -1) */
    (void)xdp_set_link_fd_compat(ifindex, -1, 0);

    return 0;
}
