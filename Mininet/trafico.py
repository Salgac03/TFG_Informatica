"""
Script que lee archivos .pcap y los envía hacia una dirección IP destino,
seleccionando aleatoriamente paquetes de diferentes conjuntos cada 200 ms.
Modifica las direcciones IP de origen y destino en los paquetes con capa IP,
y siempre autogenera la capa Ethernet, sin importar si el paquete capturado ya la tenía.
"""

from scapy.all import (
    PcapReader,
    IP,
    send,
    sendp,
    Ether,
    get_if_hwaddr,
    conf
)
import argparse
import time
import random
from typing import List, Iterator

def send_packets(packets, ip_src, ip_dst):
    """
    Procesa y envía una lista de paquetes:
      - Si el paquete tiene capa IP:
         * Se actualizan los campos de IP.
         * Se elimina la cabecera Ethernet (si existe) para que el kernel la regenere
           automaticamente mediante ARP.
         * Se envía con send().
      - Si el paquete NO tiene capa IP:
         * Se descarta cualquier cabecera Ethernet existente.
         * Se crea de nuevo la cabecera Ethernet usando la MAC de la interfaz actual
           (como origen) y broadcast como destino.
         * Se envía con sendp().
    """
    sent_count = 0
    # Obtenemos la dirección MAC de la interfaz de envío (la que usa scapy por defecto)
    src_mac = get_if_hwaddr(conf.iface)
    for packet in packets:
        try:
            if packet.haslayer(IP):
                # Actualizamos las direcciones IP
                packet[IP].src = ip_src
                packet[IP].dst = ip_dst

                # Eliminar siempre la cabecera Ethernet (si la hay) para que el kernel la regenere
                packet = packet[IP]
                
                # Se envía como paquete de Capa 3. El kernel se encargará de construir la cabecera Ethernet
                # usando ARP.
                send(packet, verbose=False)
            else:
                # Para paquetes sin capa IP: 
                # Si tienen una capa Ethernet, descártala (usando .payload) para volver a generar una.
                if packet.haslayer(Ether):
                    packet = packet.payload
                # Agregamos una cabecera Ethernet nueva usando la MAC detectada y destino broadcast.
                new_packet = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / packet
                sendp(new_packet, verbose=False)
            sent_count += 1
        except Exception as e:
            print(f"Error al enviar el paquete: {e}")
    return sent_count

def packet_generator(filenames: List[str]) -> Iterator:
    """
    Generador que lee paquetes desde cada archivo .pcap sin cargarlos todos en memoria.
    """
    for filename in filenames:
        try:
            with PcapReader(filename) as packets:
                for packet in packets:
                    yield packet
        except Exception as e:
            print(f"Error al abrir o leer el archivo pcap {filename}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Script para enviar paquetes desde un host a otro usando archivos pcap. " +
                    "Se autogenera la capa Ethernet, ignorando la que tengan los paquetes capturados."
    )
    parser.add_argument('-m', '--mfiles', nargs='+', help='Lista de archivos pcap (-m)', required=True)
    parser.add_argument('-l', '--lfiles', nargs='+', help='Lista de archivos pcap (-l)', required=True)
    parser.add_argument('--ip_src', type=str, help='Dirección IP de origen', required=True)
    parser.add_argument('--ip_dst', type=str, help='Dirección IP de destino', required=True)
    args = parser.parse_args()

    ip_src = args.ip_src
    ip_dst = args.ip_dst

    mfiles_generator = packet_generator(args.mfiles)
    lfiles_generator = packet_generator(args.lfiles)

    count_mfiles = 0
    count_lfiles = 0

    try:
        while True:
            random_number = random.randint(0, 100)
            packets_to_send = []
            sent_this_iteration = 0

            if random_number % 2 == 0:
                for _ in range(4):
                    try:
                        packet = next(lfiles_generator)
                        packets_to_send.append(packet)
                    except StopIteration:
                        print("Se alcanzaron todos los paquetes de los archivos -l.")
                        break
                sent_this_iteration = send_packets(packets_to_send, ip_src, ip_dst)
                count_lfiles += sent_this_iteration
            else:
                for _ in range(4):
                    try:
                        packet = next(mfiles_generator)
                        packets_to_send.append(packet)
                    except StopIteration:
                        print("Se alcanzaron todos los paquetes de los archivos -m.")
                        break
                sent_this_iteration = send_packets(packets_to_send, ip_src, ip_dst)
                count_mfiles += sent_this_iteration

            time.sleep(0.2)

    except KeyboardInterrupt:
        print("\nScript interrumpido manualmente.")

    print("\nResumen:")
    print(f"Paquetes enviados desde archivos -m: {count_mfiles}")
    print(f"Paquetes enviados desde archivos -l: {count_lfiles}")

if __name__ == '__main__':
    main()
