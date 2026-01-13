#!/usr/bin/env python3
import argparse, os, random, sys, time
from typing import Iterator, List, Optional, Tuple
from scapy.all import PcapReader, Ether, conf, get_if_hwaddr, getmacbyip

def pick_iface() -> str:
    for n in sorted(os.listdir("/sys/class/net")):
        if n != "lo" and not n.startswith(("ovs","docker","br-","virbr","veth")):
            return n
    raise SystemExit("No pude autodetectar interfaz. Usa --iface.")

def resolve_macs(iface: str, src: Optional[str], dst: Optional[str], dst_ip: Optional[str]) -> Tuple[str,str]:
    src = src or get_if_hwaddr(iface)
    if not dst:
        if not dst_ip: raise SystemExit("Falta destino: usa --dst-mac o --dst-ip.")
        dst = getmacbyip(dst_ip)
        if not dst: raise SystemExit(f"No pude resolver MAC para {dst_ip}. (haz ping/ARP primero)")
    return src, dst

def stream_pcaps(files: List[str]) -> Iterator:
    while True:  # siempre en bucle: si se acaba, reabre
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
    p = pkt.copy()
    if p.haslayer(Ether):
        p[Ether].src, p[Ether].dst = eth.src, eth.dst
    else:
        p = eth / p
    return bytes(p)

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generador L2 sencillo por rachas (bursts): alterna tráfico LEGIT/MAL al azar cada N ms."
    )
    ap.add_argument("--legit", nargs="+", required=True, help="PCAP(s) de tráfico legítimo")
    ap.add_argument("--mal",   nargs="+", required=True, help="PCAP(s) de tráfico malicioso/malware")

    ap.add_argument("--duration", type=float, default=10.0, help="segundos totales")
    ap.add_argument("--burst-ms", type=int, default=200, help="duración de cada racha en ms")
    ap.add_argument("--p-mal", type=float, default=0.5, help="probabilidad de que una racha sea MAL (0..1)")

    ap.add_argument("--rate", type=int, default=0, help="pps objetivo (0=sin limitación)")
    ap.add_argument("--batch", type=int, default=64, help="paquetes por batch (mejor rendimiento)")

    ap.add_argument("--iface", default=None, help="interfaz de salida (si no, autodetecta)")
    ap.add_argument("--src-mac", default=None)
    ap.add_argument("--dst-mac", default=None)
    ap.add_argument("--dst-ip",  default=None)

    ap.add_argument("--seed", type=int, default=None, help="semilla RNG (reproducible)")
    a = ap.parse_args()

    if a.seed is not None: random.seed(a.seed)
    if not (0.0 <= a.p_mal <= 1.0): raise SystemExit("--p-mal debe estar entre 0 y 1")
    if a.burst_ms <= 0: raise SystemExit("--burst-ms debe ser > 0")

    iface = a.iface or pick_iface()
    src, dst = resolve_macs(iface, a.src_mac, a.dst_mac, a.dst_ip)
    eth = Ether(src=src, dst=dst)

    gen_legit = stream_pcaps(a.legit)
    gen_mal   = stream_pcaps(a.mal)

    sock = conf.L2socket(iface=iface)
    batch = max(1, a.batch)
    rate = max(0, a.rate)
    interval = (batch / rate) if rate else 0.0

    sent_legit = sent_mal = bursts_legit = bursts_mal = 0
    t0 = time.perf_counter()
    next_t = t0

    try:
        while (time.perf_counter() - t0) < a.duration:
            is_mal = (random.random() < a.p_mal)
            gen = gen_mal if is_mal else gen_legit
            if is_mal: bursts_mal += 1
            else:      bursts_legit += 1

            burst_end = time.perf_counter() + (a.burst_ms / 1000.0)

            while time.perf_counter() < burst_end and (time.perf_counter() - t0) < a.duration:
                raws = [to_raw(next(gen), eth) for _ in range(batch)]
                for r in raws: sock.send(r)

                if is_mal: sent_mal += batch
                else:      sent_legit += batch

                if interval:
                    next_t += interval
                    s = next_t - time.perf_counter()
                    if s > 0: time.sleep(s)
                    else: next_t = time.perf_counter()

    except KeyboardInterrupt:
        print("[INFO] Interrumpido.", file=sys.stderr)
    finally:
        try: sock.close()
        except Exception: pass

    dt = time.perf_counter() - t0
    total = sent_legit + sent_mal
    pps = (total / dt) if dt else 0.0
    print(f"[OK] iface={iface} total={total} pps≈{pps:.1f} legit={sent_legit} mal={sent_mal} bursts(L/M)={bursts_legit}/{bursts_mal} elapsed={dt:.3f}s")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
