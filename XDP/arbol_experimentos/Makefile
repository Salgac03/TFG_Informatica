# Compilador y opciones
CLANG = clang
CC = gcc
CFLAGS = -O2

# Detectar multiarch para includes
MULTIARCH := $(shell gcc -print-multiarch)

# Detectar arquitectura para __TARGET_ARCH_*
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	BPF_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
	BPF_ARCH := arm64
else ifeq ($(UNAME_M),armv7l)
	BPF_ARCH := arm
else ifeq ($(UNAME_M),ppc64le)
	BPF_ARCH := powerpc
else
	# fallback (puedes ajustar si tu arch es otra)
	BPF_ARCH := x86
endif

# Flags para compilar correctamente BPF (eBPF)
BPF_FLAGS = -target bpf -D__TARGET_ARCH_$(BPF_ARCH)

# Rutas de inclusión
KERNEL_INCLUDES = -I/usr/include/$(MULTIARCH) -I/usr/include -I.

# flags/libs correctos para libbpf
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf 2>/dev/null) -ldl

# Archivos fuente y de salida
KERN_SRC = xdp_kern.c
USR_SRC = xdp_usr.c
KERN_OBJ = xdp_kern.o
USR_BIN = xdp_usr

# Regla por defecto: compilar ambos programas
all: $(KERN_OBJ) $(USR_BIN)

# Compilar el programa del kernel (eBPF)
$(KERN_OBJ): $(KERN_SRC)
	$(CLANG) $(BPF_FLAGS) $(KERNEL_INCLUDES) -g -O2 -c $(KERN_SRC) -o $(KERN_OBJ)

# Compilar el programa de espacio de usuario
$(USR_BIN): $(USR_SRC)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(USR_SRC) -o $(USR_BIN) $(LIBBPF_LIBS)

# Limpiar archivos generados
clean:
	rm -f $(KERN_OBJ) $(USR_BIN)
