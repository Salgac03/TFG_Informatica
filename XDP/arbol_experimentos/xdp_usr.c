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


static volatile sig_atomic_t stop;

static void handle_sigint(int sig)
{
    (void)sig;
    stop = 1;
}

/* Abre libbpf explícitamente (evita RTLD_DEFAULT) */
static void *dlopen_libbpf(void)
{
    void *h = dlopen("libbpf.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!h)
        h = dlopen("libbpf.so", RTLD_NOW | RTLD_LOCAL);
    return h;
}

/* Compat: usa la API XDP que exista en la libbpf del sistema
 * Prioridad:
 *  1) bpf_xdp_attach/bpf_xdp_detach (preferida en libbpf modernas: 1.3+)
 *  2) bpf_set_link_xdp_fd_opts (legacy intermedia)
 *  3) bpf_set_link_xdp_fd (legacy antigua: funciona en 0.5 típicamente)
 *
 * Importante: usamos typedefs con 'const void *' para opts para no depender
 * de structs nuevas en headers viejos.
 */
static int xdp_attach_compat(int ifindex, int prog_fd, __u32 flags)
{
    void *handle = dlopen_libbpf();
    void *sym;

    if (!handle)
        return -ENOSYS;

    /* 1) API moderna */
    sym = dlsym(handle, "bpf_xdp_attach");
    if (sym) {
        int (*fn)(int, int, __u32, const void *) =
            (int (*)(int, int, __u32, const void *))sym;
        int ret = fn(ifindex, prog_fd, flags, NULL);
        dlclose(handle);
        return ret;
    }

    /* 2) Legacy con opts */
    sym = dlsym(handle, "bpf_set_link_xdp_fd_opts");
    if (sym) {
        int (*fn)(int, int, __u32, const void *) =
            (int (*)(int, int, __u32, const void *))sym;
        int ret = fn(ifindex, prog_fd, flags, NULL);
        dlclose(handle);
        return ret;
    }

    /* 3) Legacy más vieja */
    sym = dlsym(handle, "bpf_set_link_xdp_fd");
    if (sym) {
        int (*fn)(int, int, __u32) = (int (*)(int, int, __u32))sym;
        int ret = fn(ifindex, prog_fd, flags);
        dlclose(handle);
        return ret;
    }

    dlclose(handle);
    return -ENOSYS;
}

static int xdp_detach_compat(int ifindex, __u32 flags)
{
    void *handle = dlopen_libbpf();
    void *sym;

    if (!handle)
        return -ENOSYS;

    /* 1) API moderna */
    sym = dlsym(handle, "bpf_xdp_detach");
    if (sym) {
        int (*fn)(int, __u32, const void *) =
            (int (*)(int, __u32, const void *))sym;
        int ret = fn(ifindex, flags, NULL);
        dlclose(handle);
        return ret;
    }

    /* 2) Legacy con opts: detach = prog_fd = -1 */
    sym = dlsym(handle, "bpf_set_link_xdp_fd_opts");
    if (sym) {
        int (*fn)(int, int, __u32, const void *) =
            (int (*)(int, int, __u32, const void *))sym;
        int ret = fn(ifindex, -1, flags, NULL);
        dlclose(handle);
        return ret;
    }

    /* 3) Legacy más vieja */
    sym = dlsym(handle, "bpf_set_link_xdp_fd");
    if (sym) {
        int (*fn)(int, int, __u32) = (int (*)(int, int, __u32))sym;
        int ret = fn(ifindex, -1, flags);
        dlclose(handle);
        return ret;
    }

    dlclose(handle);
    return -ENOSYS;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    int prog_fd = -1;
    int ifindex;
    __u32 xdp_flags = 0; /* puedes cambiar a XDP_FLAGS_SKB_MODE, etc. */

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


    prog = bpf_object__find_program_by_name(obj, "ransomware_tree");
    if (!prog) {
        fprintf(stderr, "Error: no se encontró el programa BPF 'ransomware_tree'\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        perror("Error al obtener FD del programa BPF");
        return 1;
    }

    int err = xdp_attach_compat(ifindex, prog_fd, xdp_flags);
    if (err < 0) {
        if (err == -ENOSYS) {
            fprintf(stderr,
                    "Error: no se pudo localizar en libbpf ninguna API XDP "
                    "(bpf_xdp_attach/detach ni bpf_set_link_xdp_fd/_opts).\n"
                    "Solución recomendada: enlazar/instalar libbpf con soporte XDP o usar libxdp (xdp-tools).\n");
        } else {
            /* muchas APIs devuelven -errno */
            errno = -err;
            perror("Error al adjuntar el programa BPF a la interfaz");
        }
        return 1;
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

	printf("Programa XDP adjuntado a la interfaz %s\n", argv[1]);
	printf("XDP activo (Ctrl+C para salir)...\n");

	while (!stop) {
		sleep(1);
	}

    /* Detach */
    (void)xdp_detach_compat(ifindex, xdp_flags);

    /* Limpieza (opcional, pero recomendable) */
    bpf_object__close(obj);
    return 0;
}
