from scapy.all import PcapReader, sendp, Ether
import argparse
import time
import random
from typing import List, Iterator

def send_packets(packets, src_mac, dst_mac, iface):
    """
    Procesa y envía una lista de paquetes:
      - Añade o actualiza la capa Ethernet con las MAC proporcionadas.
    """
    sent_count = 0
    for packet in packets:
        try:
            # Si el paquete no tiene capa Ethernet, la añadimos.
            if not packet.haslayer(Ether):
                packet = Ether(src=src_mac, dst=dst_mac) / packet
            else:
                # Actualizamos las direcciones MAC de origen y destino
                packet[Ether].src = src_mac
                packet[Ether].dst = dst_mac
            
            # Enviar el paquete a nivel 2
            sendp(packet, iface=iface, verbose=False)
            sent_count += 1
        except Exception as e:
            print(f"Error al enviar el paquete: {e}")
    return sent_count

def packet_generator(filenames: List[str]) -> Iterator:
    """
    Generador que lee paquetes desde archivos .pcap sin cargarlos todos en memoria.
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
                    "Se configuran las direcciones MAC en la capa Ethernet."
    )
    parser.add_argument('-m', '--mfiles', nargs='+', help='Lista de archivos pcap (-m)', required=True)
    parser.add_argument('-l', '--lfiles', nargs='+', help='Lista de archivos pcap (-l)', required=True)
    parser.add_argument('--src_mac', type=str, help='Dirección MAC de origen', required=True)
    parser.add_argument('--dst_mac', type=str, help='Dirección MAC de destino', required=True)
    parser.add_argument('--iface', type=str, help='Interfaz de red para enviar los paquetes', required=True)
    args = parser.parse_args()

    src_mac = args.src_mac
    dst_mac = args.dst_mac
    iface = args.iface

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
                for _ in range(4):  # Selecciona 4 paquetes del conjunto -l
                    try:
                        packet = next(lfiles_generator)
                        packets_to_send.append(packet)
                    except StopIteration:
                        print("Se alcanzaron todos los paquetes de los archivos -l.")
                        break
                sent_this_iteration = send_packets(packets_to_send, src_mac, dst_mac, iface)
                count_lfiles += sent_this_iteration
            else:
                for _ in range(4):  # Selecciona 4 paquetes del conjunto -m
                    try:
                        packet = next(mfiles_generator)
                        packets_to_send.append(packet)
                    except StopIteration:
                        print("Se alcanzaron todos los paquetes de los archivos -m.")
                        break
                sent_this_iteration = send_packets(packets_to_send, src_mac, dst_mac, iface)
                count_mfiles += sent_this_iteration

            time.sleep(0.2)  # Retraso de 200 ms entre iteraciones

    except KeyboardInterrupt:
        print("\nScript interrumpido manualmente.")

    print("\nResumen:")
    print(f"Paquetes enviados desde archivos -m: {count_mfiles}")
    print(f"Paquetes enviados desde archivos -l: {count_lfiles}")

if __name__ == '__main__':
    main()
