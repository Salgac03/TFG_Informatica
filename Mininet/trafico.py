'''
Script python que lee archivos .pcap y los envía por la red a una ip_dst,
seleccionando aleatoriamente paquetes de diferentes conjuntos cada 500 ms y
modificando las direcciones MAC de origen y destino.
'''

from scapy.all import PcapReader, IP, Ether, sendp
import argparse
import time
import random
from typing import List, Iterator

def send_packets(packets, ip_src, ip_dst, eth_src, eth_dst):
    """Envía una lista de paquetes modificando las direcciones IP y MAC."""
    for packet in packets:
        try:
            if packet.haslayer(IP):
                # Modificar IPs
                packet[IP].src = ip_src
                packet[IP].dst = ip_dst
                
            if packet.haslayer(Ether):
                # Modificar MACs
                packet[Ether].src = eth_src
                packet[Ether].dst = eth_dst
                
            sendp(packet, verbose=False)
        except Exception as e:
            print(f"Error al enviar el paquete: {e}")

def packet_generator(filenames: List[str]) -> Iterator:
    """Generador que lee paquetes de una lista de archivos pcap sin cargarlos todos en memoria."""
    for filename in filenames:
        try:
            with PcapReader(filename) as packets:
                for packet in packets:
                    yield packet
        except Exception as e:
            print(f"Error al abrir o leer el archivo pcap {filename}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Script para enviar paquetes desde un host a otro usando archivos pcap.")
    parser.add_argument('-m', '--mfiles', nargs='+', help='Lista de archivos pcap (-m)', required=True)
    parser.add_argument('-l', '--lfiles', nargs='+', help='Lista de archivos pcap (-l)', required=True)
    parser.add_argument('--ip_src', type=str, help='Dirección IP de origen del host actual', required=True)
    parser.add_argument('--ip_dst', type=str, help='Dirección IP de destino del host remoto', required=True)
    parser.add_argument('--eth_src', type=str, help='Dirección MAC de origen', required=True)
    parser.add_argument('--eth_dst', type=str, help='Dirección MAC de destino', required=True)

    args = parser.parse_args()

    ip_src = args.ip_src
    ip_dst = args.ip_dst
    eth_src = args.eth_src
    eth_dst = args.eth_dst
    mfiles_generator = packet_generator(args.mfiles)
    lfiles_generator = packet_generator(args.lfiles)

    count_mfiles = 0
    count_lfiles = 0

    try:
        while True:
            random_number = random.randint(0, 100)
            packets_to_send = []

            if random_number % 2 == 0:
                for _ in range(4):
                    try:
                        packet = next(lfiles_generator)
                        packets_to_send.append(packet)
                        count_lfiles += 1
                    except StopIteration:
                        print("Se alcanzaron todos los paquetes de los archivos -l.")
                        break
            else:
                for _ in range(4):
                    try:
                        packet = next(mfiles_generator)
                        packets_to_send.append(packet)
                        count_mfiles += 1
                    except StopIteration:
                        print("Se alcanzaron todos los paquetes de los archivos -m.")
                        break

            if packets_to_send:
                send_packets(packets_to_send, ip_src, ip_dst, eth_src, eth_dst)

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\nScript interrumpido manualmente.")

    print("\nResumen:")
    print(f"Paquetes enviados desde archivos -m: {count_mfiles}")
    print(f"Paquetes enviados desde archivos -l: {count_lfiles}")

if __name__ == '__main__':
    main()
