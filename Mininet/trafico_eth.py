from scapy.all import PcapReader, sendp, Ether
import argparse
import time
import random
import csv
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
    parser.add_argument('--rate', type=int, default=100, help='Tasa de envío en paquetes por segundo (pps)')
    parser.add_argument('--duration', type=int, default=10, help='Duración de la transmisión en segundos')
    parser.add_argument('--log', type=str, help='Archivo CSV para registrar los envíos', default=None)
    args = parser.parse_args()

    src_mac = args.src_mac
    dst_mac = args.dst_mac
    iface = args.iface
    rate = args.rate
    duration = args.duration

    mfiles_generator = packet_generator(args.mfiles)
    lfiles_generator = packet_generator(args.lfiles)

    count_mfiles = 0
    count_lfiles = 0
    pid = 0

    # Configurar log si se pide
    logfile = None
    writer = None
    if args.log:
        logfile = open(args.log, 'w', newline='')
        writer = csv.writer(logfile)
        writer.writerow(["id", "timestamp_ms", "label"])

    start_time = time.time()
    next_time = start_time
    
    # ------------------------------------------------------------------
    # CAMBIO CRUCIAL: Ajustar el intervalo por el tamaño del lote (4 paquetes)
    # interval ahora representa el tiempo que debe pasar entre cada lote de 4,
    # para que la tasa total sea igual a 'rate'.
    # ------------------------------------------------------------------
    LOTE_SIZE = 4
    if rate > 0:
        interval = LOTE_SIZE / rate
    else:
        interval = 0 # Evitar división por cero

    try:
        while time.time() - start_time < duration:
            random_number = random.randint(0, 100)
            label = "l" if random_number % 2 == 0 else "m"

            packets_to_send = []
            for _ in range(LOTE_SIZE): # enviar 4 paquetes por iteración
                try:
                    if label == "l":
                        packet = next(lfiles_generator)
                        count_lfiles += 1
                    else:
                        packet = next(mfiles_generator)
                        count_mfiles += 1
                    packets_to_send.append(packet)
                except StopIteration:
                    print(f"Se agotaron los paquetes de los archivos -{label}.")
                    break

            if packets_to_send:
                send_packets(packets_to_send, src_mac, dst_mac, iface)

                if writer:
                    ts_ms = int(time.time() * 1000)
                    for _ in packets_to_send:
                        writer.writerow([pid, ts_ms, label])
                        pid += 1

            # Control de tasa: espera hasta el siguiente instante (usando el intervalo corregido)
            next_time += interval
            sleep_time = next_time - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)
            else:
                next_time = time.time()
    except KeyboardInterrupt:
        print("\nScript interrumpido manualmente.")
    finally:
        if logfile:
            logfile.close()

    print("\nResumen:")
    print(f"Paquetes enviados desde archivos -m: {count_mfiles}")
    print(f"Paquetes enviados desde archivos -l: {count_lfiles}")

if __name__ == '__main__':
    main()
