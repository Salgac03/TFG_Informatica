# Compilador y opciones
CLANG = clang
CC = gcc
CFLAGS = -O2
BPF_FLAGS = -target bpf -g -Wall -D__BPF_TRACING__  # Opciones para compilar correctamente BPF

# Archivos fuente y de salida
KERN_SRC = xdp_kern.c
USR_SRC = xdp_usr.c
KERN_OBJ = xdp_kern.o
USR_BIN = xdp_usr

# Regla por defecto: compilar ambos programas
all: $(KERN_OBJ) $(USR_BIN)

# Compilar el programa del kernel
$(KERN_OBJ): $(KERN_SRC)
	$(CLANG) $(BPF_FLAGS) -mcpu=v3 -c $(KERN_SRC) -o $(KERN_OBJ)  # Usar -c para evitar el enlace

# Compilar el programa de espacio de usuario
$(USR_BIN): $(USR_SRC)
	$(CC) $(CFLAGS) $(USR_SRC) -o $(USR_BIN) -lbpf

# Limpiar archivos generados
clean:
	rm -f $(KERN_OBJ) $(USR_BIN)

