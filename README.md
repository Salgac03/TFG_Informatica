# TFG_Informatica
Este repositorio tiene como objetivo llevar un registro histórico sobre la realización de mi TFG

En el repositorio no se encontrará unicamente el proyecto realizado, también se encontrarán todas las pruebas
que he hecho con las diferentes tecnologías usadas en el proyecto y las actas de reunión con mi profesor de TFG.

## Descripción del proyecto
El proyecto consiste en entrenar un árbol de decisión con paquetes de red legítimos y ransomware usando python,
después este arbol python se transcribe a un árbol programado en C que filtra usando BPF/XDP. Para realiazar las
pruebas inicial Mininet.

El proyecto tiene como objetivo analizar tanto la posibilidad de implementar esta clase de mecanismos que trabajan
a nivel de kernel como ver si una vez implementados perjudican de manera significativa al uso de recursos y velocidad
de la red.

### eBPF y XDP
Como dice la página de Wikipedia a la que te redirige la página oficial de eBPF: "eBPF es una tecnología que puede ejecutar 
programas en un contexto privilegiado como el núcleo del sistema operativo. Es el sucesor del mecanismo de filtrado Berkeley
Packet Filter (BPF, donde la "e" originalmente significa "extended") en Linux y también se utiliza en partes del núcleo de 
Linux que no son de red." [1]

Sobre eBPF se desarrolló XDP que "XDP o eXpress Data Path proporciona una ruta de datos de red programable y de alto rendimiento
en el kernel de Linux. XDP proporciona procesamiento de paquetes sin sistema operativo en el nivel más bajo de la pila de software." [2]

## Citas
[1] W. contributos, “EBPF,” Wikipedia, https://en.wikipedia.org/wiki/EBPF (accessed Apr. 18, 2025). 
[2] J. Dangaard, “Introduction¶,” Introduction - Prototype Kernel 0.0.1 documentation, https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/introduction.html#what-is-xdp (accessed Apr. 18, 2025). 
