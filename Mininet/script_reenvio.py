#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
script_reenvío.py

Reenvío (replay) de una mezcla por ráfagas de dos PCAPs (legítimo y malicioso)
a un PPS objetivo durante una duración, delegando el pacing a tcpreplay.

Requisitos:
- tcpreplay instalado en el sistema (NO es pip):
    Ubuntu/Debian: sudo apt-get update && sudo apt-get install -y tcpreplay

Uso típico:
    sudo python3 script_reenvío.py --legit legit.pcap --mal mal.pcap --iface hsrc-eth0 --pps 64 --duration 10 --seed 123
"""

import argparse
import math
import random
import subprocess
import time
from dataclasses import dataclass


@dataclass
class BurstPlan:
    pcap_path: str
    packets: int


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def compute_burst_seconds(pps: float, k_packets: int, tmin_s: float, tmax_s: float) -> float:
    """
    Calcula un tiempo de ráfaga "universal" para un PPS dado, intentando que haya ~k_packets por ráfaga,
    y acotando el tiempo entre [tmin_s, tmax_s].
    """
    ideal = k_packets / pps
    return clamp(ideal, tmin_s, tmax_s)


def compute_pps_multi(pps: float, min_sleep_s: float) -> int:
    """
    Elige un --pps-multi para tcpreplay de forma que el "sleep" interno no sea demasiado pequeño:
        multi / pps >= min_sleep_s
    """
    return max(1, int(math.ceil(pps * min_sleep_s)))


def run_tcpreplay_burst(
    iface: str,
    pcap_path: str,
    pps: float,
    packets: int,
    pps_multi: int,
    stats_interval: int,
    enable_file_cache: bool,
    dry_run: bool,
) -> None:
    """
    Ejecuta una ráfaga: envía 'packets' paquetes del PCAP a 'pps' por la interfaz 'iface'.
    """
    cmd = [
        "tcpreplay",
        "--intf1", iface,
        "--pps", str(pps),
        "--pps-multi", str(pps_multi),
        "--loop", "0",          # repite el pcap indefinidamente si hace falta
        "--limit", str(packets) # pero se detiene tras N paquetes
    ]

    if stats_interval and stats_interval > 0:
        cmd += ["--stats", str(stats_interval)]

    if enable_file_cache:
        cmd.append("--enable-file-cache")

    cmd.append(pcap_path)

    if dry_run:
        print("[DRY RUN]", " ".join(cmd))
        return

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    if proc.returncode != 0:
        raise RuntimeError(f"tcpreplay failed (rc={proc.returncode}). Output:\n{proc.stdout}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Reenvío (replay) con mezcla por ráfagas de PCAP legítimo/malicioso a un PPS objetivo usando tcpreplay."
    )
    ap.add_argument("--legit", required=True, help="Ruta al PCAP legítimo")
    ap.add_argument("--mal", required=True, help="Ruta al PCAP malicioso")
    ap.add_argument("--iface", required=True, help="Interfaz de salida (p.ej. hsrc-eth0, eth0, ens3)")
    ap.add_argument("--pps", type=float, required=True, help="PPS objetivo (p.ej. 64, 128, ..., 16384)")
    ap.add_argument("--duration", type=float, required=True, help="Duración total en segundos (p.ej. 10)")
    ap.add_argument("--prob-mal", type=float, default=0.5, help="Probabilidad de escoger ráfaga maliciosa [0..1]")
    ap.add_argument("--seed", type=int, default=None, help="Semilla aleatoria (para reproducibilidad). Si no se pone, será aleatorio distinto en cada ejecución.")
    ap.add_argument("--k", type=int, default=256, help="Paquetes objetivo por ráfaga (antes de clamp Tmin/Tmax)")
    ap.add_argument("--tmin-ms", type=float, default=50.0, help="Tiempo mínimo de ráfaga en ms")
    ap.add_argument("--tmax-ms", type=float, default=1000.0, help="Tiempo máximo de ráfaga en ms")
    ap.add_argument("--min-sleep-us", type=float, default=500.0,
                    help="Busca que el sleep interno de tcpreplay sea >= este valor (microsegundos) usando --pps-multi")
    ap.add_argument("--stats", type=int, default=0, help="Intervalo de stats de tcpreplay en segundos (0 desactiva)")
    ap.add_argument("--no-file-cache", action="store_true", help="Desactivar --enable-file-cache de tcpreplay")
    ap.add_argument("--dry-run", action="store_true", help="Imprime comandos tcpreplay sin ejecutarlos")
    args = ap.parse_args()

    if not (0.0 <= args.prob_mal <= 1.0):
        raise SystemExit("--prob-mal debe estar entre 0 y 1")

    if args.pps <= 0 or args.duration <= 0:
        raise SystemExit("--pps y --duration deben ser > 0")

    if args.seed is not None:
        random.seed(args.seed)

    tmin_s = args.tmin_ms / 1000.0
    tmax_s = args.tmax_ms / 1000.0
    min_sleep_s = args.min_sleep_us / 1_000_000.0

    burst_s = compute_burst_seconds(args.pps, args.k, tmin_s, tmax_s)
    burst_packets_nominal = max(1, int(round(args.pps * burst_s)))

    pps_multi = compute_pps_multi(args.pps, min_sleep_s)
    enable_file_cache = not args.no_file_cache

    print("=== script_reenvío settings ===")
    print(f"iface={args.iface}")
    print(f"pps_target={args.pps}")
    print(f"duration={args.duration}s")
    print(f"prob_mal={args.prob_mal} seed={args.seed}")
    print(f"burst_time={burst_s*1000:.1f} ms  (~{burst_packets_nominal} pkts/burst)")
    print(f"tcpreplay: --pps-multi={pps_multi}  file_cache={enable_file_cache}  stats={args.stats}")
    print("===============================")

    start = time.monotonic()
    bursts = 0
    pkts_sent_planned = 0

    while True:
        elapsed = time.monotonic() - start
        remaining_time = args.duration - elapsed
        if remaining_time <= 0:
            break

        # Ajuste para cuadrar el total esperado en el tiempo restante.
        remaining_packets_target = int(round(args.pps * remaining_time))
        if remaining_packets_target <= 0:
            break

        burst_packets = min(burst_packets_nominal, remaining_packets_target)

        choose_mal = (random.random() < args.prob_mal)
        pcap = args.mal if choose_mal else args.legit

        bursts += 1
        pkts_sent_planned += burst_packets

        print(
            f"[burst {bursts}] type={'MAL' if choose_mal else 'LEGIT'} "
            f"pkts={burst_packets} elapsed={elapsed:.3f}s remaining={remaining_time:.3f}s"
        )

        run_tcpreplay_burst(
            iface=args.iface,
            pcap_path=pcap,
            pps=args.pps,
            packets=burst_packets,
            pps_multi=pps_multi,
            stats_interval=args.stats,
            enable_file_cache=enable_file_cache,
            dry_run=args.dry_run,
        )

    total_elapsed = time.monotonic() - start
    achieved_pps_est = pkts_sent_planned / total_elapsed if total_elapsed > 0 else 0.0

    print("=== done ===")
    print(f"bursts={bursts}")
    print(f"planned_packets={pkts_sent_planned}")
    print(f"elapsed={total_elapsed:.3f}s")
    print(f"estimated_pps={achieved_pps_est:.2f} (planned packets / wall time)")
    print("============")


if __name__ == "__main__":
    main()
