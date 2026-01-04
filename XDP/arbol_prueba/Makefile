# Compilador y opciones
CLANG = clang
CC = gcc
CFLAGS = -O2
BPF_FLAGS = -target bpf  # Opciones para compilar correctamente BPF

MULTIARCH := $(shell gcc -print-multiarch)

# Rutas de inclusión para el kernel
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

# Compilar el programa del kernel
$(KERN_OBJ): $(KERN_SRC)
	$(CLANG) $(BPF_FLAGS) $(KERNEL_INCLUDES) -g -O2 -mcpu=v1 -c $(KERN_SRC) -o $(KERN_OBJ)

# Compilar el programa de espacio de usuario
$(USR_BIN): $(USR_SRC)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(USR_SRC) -o $(USR_BIN) $(LIBBPF_LIBS)

# Limpiar archivos generados
clean:
	rm -f $(KERN_OBJ) $(USR_BIN)
