#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""trafico_eth_v2.py

Generador de tráfico Ethernet (Scapy) mezclando PCAPs legítimo/maligno.

Cambios v2 (para tu suite):
- Batch dinámico en función de PPS y burst_ms para que a PPS bajos no se envíen ráfagas artificiales enormes.
- Salida [OK] estable y parseable:
    total=... pps≈... legit=... mal=... elapsed=...s
- Mantiene compatibilidad con flags existentes (--src-mac/--dst-mac, etc.)

Ejemplo:
  sudo /home/milenka/Desktop/entorno_tfg/bin/python trafico_eth_v2.py \
    --legit ../../Legitimo.pcap --mal ../../CryLock_24012021.pcap \
    --rate 200 --duration 20 --iface hsrc-eth0 \
    --src-mac 00:00:00:00:01:01 --dst-mac 00:00:00:00:02:02 --dst-ip 10.0.0.2
"""

import argparse
import os
import random
import sys
import time
from typing import Iterator, List, Optional, Tuple

from scapy.all import PcapReader, Ether, conf, get_if_hwaddr, getmacbyip


def pick_iface() -> str:
    for n in sorted(os.listdir("/sys/class/net")):
        if n != "lo" and not n.startswith(("ovs", "docker", "br-", "virbr", "veth")):
            return n
    raise SystemExit("No pude autodetectar interfaz. Usa --iface.")


def resolve_macs(iface: str, src: Optional[str], dst: Optional[str], dst_ip: Optional[str]) -> Tuple[str, str]:
    src = src or get_if_hwaddr(iface)
    if not dst:
        if not dst_ip:
            raise SystemExit("Falta destino: usa --dst-mac o --dst-ip.")
        dst = getmacbyip(dst_ip)
        if not dst:
            raise SystemExit(f"No pude resolver MAC para {dst_ip}. (haz ping/ARP primero)")
    return src, dst


def stream_pcaps(files: List[str]) -> Iterator:
    """Itera paquetes de uno o varios PCAPs en bucle infinito."""
    while True:
        for fn in files:
            try:
                with PcapReader(fn) as pr:
                    for pkt in pr:
                        yield pkt
            except Exception as e:
                print(f"[WARN] {fn}: {e}", file=sys.stderr)
        if not files:
            return


def to_raw(pkt, eth: Ether) -> bytes:
    """Devuelve bytes Ethernet con MACs forzadas (src/dst) manteniendo payload."""
    p = pkt.copy()
    if p.haslayer(Ether):
        p[Ether].src = eth.src
        p[Ether].dst = eth.dst
        return bytes(p)

    # Si el PCAP no tiene capa Ether, encapsulamos:
    return bytes(eth / bytes(p))


def compute_dynamic_batch(rate_pps: float, burst_ms: int, batch_max: int) -> int:
    """Calcula un batch razonable para que cada burst represente ~burst_ms de tráfico a rate_pps."""
    if rate_pps <= 0:
        return max(1, batch_max)
    burst_s = max(1e-6, burst_ms / 1000.0)
    expected = int(round(rate_pps * burst_s))
    expected = max(1, expected)
    return min(max(1, batch_max), expected)


def main() -> int:
    ap = argparse.ArgumentParser(description="Scapy L2 sender mixing legit/mal PCAPs.")
    ap.add_argument("--legit", required=True, nargs="+", help="PCAP(s) legítimo(s)")
    ap.add_argument("--mal", required=True, nargs="+", help="PCAP(s) maligno(s)")
    ap.add_argument("--duration", type=float, default=10.0, help="Segundos totales")
    ap.add_argument("--burst-ms", type=int, default=200, help="Ventana objetivo de burst (ms)")
    ap.add_argument("--p-mal", type=float, default=0.5, help="Probabilidad de burst maligno")
    ap.add_argument("--rate", type=float, default=0.0, help="PPS objetivo (0=best effort)")
    ap.add_argument("--batch", type=int, default=64, help="Batch máximo por iteración (cap)")
    ap.add_argument("--iface", default=None, help="Interfaz de salida (default: autodetect)")
    ap.add_argument("--src-mac", dest="src_mac", default=None)
    ap.add_argument("--dst-mac", dest="dst_mac", default=None)
    ap.add_argument("--dst-ip", dest="dst_ip", default=None)
    ap.add_argument("--seed", type=int, default=None, help="Semilla RNG (opcional)")
    a = ap.parse_args()

    if a.seed is not None:
        random.seed(a.seed)

    iface = a.iface or pick_iface()
    src_mac, dst_mac = resolve_macs(iface, a.src_mac, a.dst_mac, a.dst_ip)

    # Ethernet template con MACs fijadas
    eth = Ether(src=src_mac, dst=dst_mac)

    gen_legit = stream_pcaps(a.legit)
    gen_mal = stream_pcaps(a.mal)

    sock = conf.L2socket(iface=iface)

    rate = max(0.0, float(a.rate))
    batch_max = max(1, int(a.batch))
    burst_ms = max(1, int(a.burst_ms))

    # batch dinámico
    batch = compute_dynamic_batch(rate, burst_ms, batch_max)
    interval = (batch / rate) if rate > 0 else 0.0

    sent_legit = 0
    sent_mal = 0
    bursts_legit = 0
    bursts_mal = 0

    t0 = time.perf_counter()
    next_t = t0

    # Log de arranque (útil para debug)
    print(
        f"[INFO] iface={iface} src={src_mac} dst={dst_mac} dst_ip={a.dst_ip or '-'} "
        f"rate_pps={rate:.1f} burst_ms={burst_ms} batch_max={batch_max} batch_dyn={batch}",
        file=sys.stderr,
    )

    try:
        while (time.perf_counter() - t0) < a.duration:
            is_mal = (random.random() < float(a.p_mal))
            gen = gen_mal if is_mal else gen_legit
            if is_mal:
                bursts_mal += 1
            else:
                bursts_legit += 1

            burst_end = time.perf_counter() + (burst_ms / 1000.0)

            # Dentro de cada burst, seguimos enviando batches hasta que expire la ventana
            # (con pacing por interval para aproximar la tasa objetivo)
            while time.perf_counter() < burst_end and (time.perf_counter() - t0) < a.duration:
                raws = [to_raw(next(gen), eth) for _ in range(batch)]
                for r in raws:
                    sock.send(r)

                if is_mal:
                    sent_mal += batch
                else:
                    sent_legit += batch

                if interval > 0:
                    next_t += interval
                    s = next_t - time.perf_counter()
                    if s > 0:
                        time.sleep(s)
                    else:
                        # si vamos tarde, re-sincronizamos
                        next_t = time.perf_counter()

    except KeyboardInterrupt:
        print("[INFO] Interrumpido.", file=sys.stderr)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    dt = time.perf_counter() - t0
    total = sent_legit + sent_mal
    pps = (total / dt) if dt else 0.0

    # IMPORTANTE: formato estable para parseo desde la suite
    print(
        f"[OK] iface={iface} total={total} pps≈{pps:.1f} legit={sent_legit} mal={sent_mal} "
        f"bursts(L/M)={bursts_legit}/{bursts_mal} elapsed={dt:.3f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
