#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_experiments_suite_v12.py

Suite completa Mininet (v12):
  1) iperf (UDP) sin XDP + con XDP
  2) tcpreplay (legit/malign) sin XDP + con XDP  (SIN tcprewrite)
  3) trafico_eth.py sin XDP + con XDP

IMPORTANTE:
- Esta v9 NO usa tcprewrite dentro de los tests.
- Para tcpreplay, se asume que los PCAPs ya están adaptados a Mininet (MACs/checksums) usando:
    prewrite_pcaps_for_mininet.py
- Para iperf y trafico_eth no hace falta tcprewrite.

Uso:
  sudo python3 run_experiments_suite_v12.py \
    --repo-root /RUTA/REPO \
    -l /RUTA/ABS/legit_mininet.pcap \
    -m /RUTA/ABS/malign_mininet.pcap

Opcional:
  --skip-iperf --skip-tcpreplay --skip-generator
  --quick   (reduce duraciones/sleeps para depurar)

Salida:
  /tmp/exp_suite_<tag>/
"""

import argparse
import csv
import json
import os
import re
import shlex
import time
from datetime import datetime

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

from redarbolrw1 import SimpleTopo


# ======================================================
# CONFIG FIJA
# ======================================================

PPS_STEPS_DEFAULT = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384]

# iperf
IPERF_PAYLOAD_LEN = 1400
IPERF_SERVER_PORT = 5201

# tcpreplay
TCPREPLAY_DURATION_DEFAULT = 10

# trafico_eth (tu generador)
GEN_DURATION_DEFAULT = 10.0
GEN_BURST_MS = 200
GEN_P_MAL = 0.5
GEN_BATCH = 64
GEN_SEED = 12345

# sleeps
SLEEP_BETWEEN_RUNS_DEFAULT = 2.0
SLEEP_BETWEEN_BLOCKS_DEFAULT = 6.0
SLEEP_BETWEEN_EXPERIMENTS_DEFAULT = 8.0

# XDP
XDP_USR_REL_PATH = "XDP/arbol_prueba/xdp_usr"

# generador
GEN_SCRIPT_REL_PATH = "Mininet/trafico_eth_v3.py"


# ======================================================
# UTILS
# ======================================================

def now_tag():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def abspath(repo_root: str, path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(repo_root, path)


def must_exist_file(path: str, what: str):
    if not os.path.isfile(path):
        raise SystemExit(f"[FATAL] {what} no existe: {path}")


def run_cmd(host, cmd: str) -> str:
    return host.cmd(cmd)


def start_bg(host, cmd: str, pidfile: str, logfile: str):
    host.cmd(f"{cmd} > {shlex.quote(logfile)} 2>&1 & echo $! > {shlex.quote(pidfile)}")


def stop_bg(host, pidfile: str):
    host.cmd(f"kill $(cat {shlex.quote(pidfile)}) >/dev/null 2>&1 || true")


def count_pcap_packets(host, pcap_path: str) -> int:
    out = host.cmd(f"tcpdump -n -r {shlex.quote(pcap_path)} 2>/dev/null | wc -l")
    try:
        return int(out.strip())
    except Exception:
        return 0


def pps_to_bitrate_bps(pps: int, payload_bytes: int) -> int:
    return int(pps) * int(payload_bytes) * 8


def start_xdp(hdst, repo_root: str, iface: str, pid_path: str, log_path: str):
    xdp_bin = os.path.join(repo_root, XDP_USR_REL_PATH)
    run_cmd(hdst, f"chmod +x {shlex.quote(xdp_bin)}")
    start_bg(hdst, f"{shlex.quote(xdp_bin)} {shlex.quote(iface)}", pid_path, log_path)


def preflight(net, suite_dir: str):
    hsrc, hdst = net["hsrc"], net["hdst"]
    tx_iface = hsrc.defaultIntf().name
    rx_iface = hdst.defaultIntf().name
    hdst_ip = hdst.IP()
    print(f"[PRE] hsrc.iface={tx_iface} hdst.iface={rx_iface} hdst.ip={hdst_ip}")
    ping_out = hsrc.cmd(f"ping -c 1 -W 1 {hdst_ip}")
    print("[PRE] ping:\n" + ping_out)


# ======================================================
# IPERF
# ======================================================

def parse_iperf_json(out: str, duration: int):
    j = json.loads(out)
    end = j.get("end", {})
    s = end.get("sum", {}) or end.get("sum_received", {}) or {}

    packets = int(s.get("packets", 0))
    lost_packets = int(s.get("lost_packets", 0))
    lost_percent = float(s.get("lost_percent", 0.0))
    bps = float(s.get("bits_per_second", 0.0))
    measured_pps = packets / duration if duration > 0 else 0.0
    return packets, lost_packets, lost_percent, bps, measured_pps


def iperf_sweep(net, results_dir: str, repo_root: str, pps_steps, duration: int, sleep_between_runs: float, sleep_between_blocks: float):
    os.makedirs(results_dir, exist_ok=True)
    raw_dir = os.path.join(results_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    hsrc, hdst = net["hsrc"], net["hdst"]
    hdst_ip = hdst.IP()
    rx_iface = hdst.defaultIntf().name

    csv_path = os.path.join(results_dir, "iperf_results.csv")
    header = [
        "timestamp","xdp","pps_target","pps_measured","bps_measured",
        "lost_percent","lost_packets","packets_total","note"
    ]

    def run_block(xdp_label: str):
        for pps in pps_steps:
            print(f"[IPERF] XDP={xdp_label} PPS={pps}")
            bitrate = pps_to_bitrate_bps(pps, IPERF_PAYLOAD_LEN)

            tag = f"{xdp_label}_pps{pps}_{now_tag()}"
            srv_log = os.path.join(raw_dir, f"iperf_srv_{tag}.log")
            srv_pid = os.path.join(raw_dir, f"iperf_srv_{tag}.pid")
            cli_raw = os.path.join(raw_dir, f"iperf_cli_{tag}.txt")

            start_bg(hdst, f"iperf3 -s -p {IPERF_SERVER_PORT}", srv_pid, srv_log)
            time.sleep(0.3)

            cmd = (
                f"iperf3 -c {hdst_ip} -p {IPERF_SERVER_PORT} "
                f"-u -t {duration} -l {IPERF_PAYLOAD_LEN} -b {bitrate} -J"
            )
            out = run_cmd(hsrc, cmd)
            with open(cli_raw, "w") as f:
                f.write(out)

            stop_bg(hdst, srv_pid)

            note = ""
            try:
                packets, lost_packets, lost_percent, bps, pps_measured = parse_iperf_json(out, duration)
            except Exception:
                packets = lost_packets = 0
                lost_percent = 0.0
                bps = pps_measured = 0.0
                note = "iperf_json_parse_failed (ver raw)"

            row = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "xdp": xdp_label,
                "pps_target": pps,
                "pps_measured": f"{pps_measured:.2f}",
                "bps_measured": f"{bps:.2f}",
                "lost_percent": f"{lost_percent:.2f}",
                "lost_packets": lost_packets,
                "packets_total": packets,
                "note": note,
            }

            write_header = not os.path.exists(csv_path)
            with open(csv_path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=header)
                if write_header:
                    w.writeheader()
                w.writerow(row)

            time.sleep(sleep_between_runs)

    print("[IPERF] sin XDP")
    run_block("off")
    time.sleep(sleep_between_blocks)

    xdp_pid = os.path.join(results_dir, "xdp_usr_iperf.pid")
    xdp_log = os.path.join(results_dir, "xdp_usr_iperf.log")
    print(f"[IPERF] Activando XDP en {rx_iface}")
    start_xdp(hdst, repo_root, rx_iface, xdp_pid, xdp_log)
    try:
        print("[IPERF] con XDP")
        run_block("on")
    finally:
        print("[IPERF] Desactivando XDP")
        stop_bg(hdst, xdp_pid)


# ======================================================
# TCPREPLAY (SIN tcprewrite)
# ======================================================

def tcpreplay_sweep(net, results_dir: str, repo_root: str, pcap_path: str, label: str,
                   pps_steps, duration: int, sleep_between_runs: float, sleep_between_blocks: float):
    hsrc, hdst = net["hsrc"], net["hdst"]
    tx_iface = hsrc.defaultIntf().name
    rx_iface = hdst.defaultIntf().name

    base_dir = os.path.join(results_dir, label)
    pcaps_dir = os.path.join(base_dir, "pcaps")
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(pcaps_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    csv_path = os.path.join(base_dir, f"tcpreplay_{label}_results.csv")
    header = [
        "timestamp","xdp","label","pps_target","pps_measured",
        "lost_percent","lost_packets","packets_total","note"
    ]

    must_exist_file(pcap_path, f"PCAP {label} (mininet prewritten)")
    print(f"[TCP] {label} usando PCAP={pcap_path}")

    def run_block(xdp_label: str):
        for pps in pps_steps:
            print(f"[TCP] {label} XDP={xdp_label} PPS={pps}")
            tag = f"{label}_{xdp_label}_pps{pps}_{now_tag()}"

            rx_pcap = os.path.join(pcaps_dir, f"rx_{tag}.pcap")
            tcpdump_log = os.path.join(logs_dir, f"tcpdump_{tag}.log")
            tcpdump_pid = os.path.join(logs_dir, f"tcpdump_{tag}.pid")
            tcpreplay_log = os.path.join(logs_dir, f"tcpreplay_{tag}.log")

            start_bg(
                hdst,
                f"timeout {duration} tcpdump -i {shlex.quote(rx_iface)} -n -U -s 0 -w {shlex.quote(rx_pcap)}",
                tcpdump_pid, tcpdump_log
            )
            time.sleep(0.6)

            # tcpreplay limitado para que dure ~{duration}s igual que tcpdump
            # Con PCAPs enormes, sin --limit tcpreplay intentaría reproducir el fichero entero y se "queda colgado" a PPS bajos.
            limit_pkts = int(round(duration * pps))
            # timeout un pelín mayor para que no corte antes de tiempo por overhead
            play_cmd = (
                f"timeout {int(duration) + 3} "
                f"tcpreplay --intf1={shlex.quote(tx_iface)} --pps={int(pps)} --limit={limit_pkts} "
                f"{shlex.quote(pcap_path)}"
            )
            out = run_cmd(hsrc, f"{play_cmd} > {shlex.quote(tcpreplay_log)} 2>&1; echo $?").strip().splitlines()
            play_rc = int(out[-1]) if out and out[-1].isdigit() else 99
            note = "" if play_rc == 0 else f"tcpreplay_rc={play_rc} (ver log)"

            time.sleep(1.0)
            stop_bg(hdst, tcpdump_pid)

            rx_pkts = count_pcap_packets(hdst, rx_pcap)
            pps_measured = (rx_pkts / duration) if duration > 0 else 0.0
            expected = int(round(duration * pps))
            lost = max(0, expected - rx_pkts)
            loss_percent = (lost / expected * 100.0) if expected > 0 else 0.0

            row = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "xdp": xdp_label,
                "label": label,
                "pps_target": pps,
                "pps_measured": f"{pps_measured:.2f}",
                "lost_percent": f"{loss_percent:.2f}",
                "lost_packets": lost,
                "packets_total": rx_pkts,
                "note": note,
            }

            write_header = not os.path.exists(csv_path)
            with open(csv_path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=header)
                if write_header:
                    w.writeheader()
                w.writerow(row)

            time.sleep(sleep_between_runs)

    print(f"[TCP] {label} sin XDP")
    run_block("off")
    time.sleep(sleep_between_blocks)

    xdp_pid = os.path.join(base_dir, f"xdp_usr_tcpreplay_{label}.pid")
    xdp_log = os.path.join(base_dir, f"xdp_usr_tcpreplay_{label}.log")
    print(f"[TCP] Activando XDP en {rx_iface} (tcpreplay {label})")
    start_xdp(hdst, repo_root, rx_iface, xdp_pid, xdp_log)
    try:
        print(f"[TCP] {label} con XDP")
        run_block("on")
    finally:
        print(f"[TCP] Desactivando XDP (tcpreplay {label})")
        stop_bg(hdst, xdp_pid)


# ======================================================
# TRAFICO_ETH
# ======================================================

GEN_OUT_RE = re.compile(
    r"total=(?P<total>\d+)\s+pps≈(?P<pps>[0-9.]+)\s+legit=(?P<legit>\d+)\s+mal=(?P<mal>\d+).*elapsed=(?P<elapsed>[0-9.]+)s"
)


def parse_gen_stdout(out: str, default_elapsed: float):
    m = GEN_OUT_RE.search(out)
    if not m:
        return {"tx_total": 0, "tx_legit": 0, "tx_mal": 0, "elapsed": float(default_elapsed)}
    return {
        "tx_total": int(m.group("total")),
        "tx_legit": int(m.group("legit")),
        "tx_mal": int(m.group("mal")),
        "elapsed": float(m.group("elapsed")),
    }


def trafico_eth_sweep(net, results_dir: str, repo_root: str, pcap_legit: str, pcap_malign: str,
                     pps_steps, duration: float, sleep_between_runs: float, sleep_between_blocks: float):
    hsrc, hdst = net["hsrc"], net["hdst"]
    tx_iface = hsrc.defaultIntf().name
    rx_iface = hdst.defaultIntf().name
    hdst_ip = hdst.IP()
    src_mac = hsrc.MAC()
    dst_mac = hdst.MAC()

    base_dir = os.path.join(results_dir, "trafico_eth")
    pcaps_dir = os.path.join(base_dir, "pcaps")
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(pcaps_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    csv_path = os.path.join(base_dir, "trafico_eth_results.csv")
    header = [
        "timestamp","xdp","label",
        "pps_target","pps_measured",
        "lost_percent","lost_packets","packets_total",
        "tx_packets_total","tx_legit_packets","tx_mal_packets",
        "note",
    ]

    gen_script = abspath(repo_root, GEN_SCRIPT_REL_PATH)
    print(f"[GEN] usando script={gen_script}")
    must_exist_file(gen_script, "trafico_eth.py")

    # Para el generador usamos los PCAPs que nos pases (pueden ser originales o prewritten; da igual)
    must_exist_file(pcap_legit, "PCAP legit para generador")
    must_exist_file(pcap_malign, "PCAP malign para generador")

    def run_block(xdp_label: str):
        for pps in pps_steps:
            print(f"[GEN] XDP={xdp_label} PPS={pps}")
            tag = f"{xdp_label}_pps{pps}_{now_tag()}"

            rx_pcap = os.path.join(pcaps_dir, f"rx_{tag}.pcap")
            tcpdump_log = os.path.join(logs_dir, f"tcpdump_{tag}.log")
            tcpdump_pid = os.path.join(logs_dir, f"tcpdump_{tag}.pid")
            gen_log = os.path.join(logs_dir, f"gen_{tag}.log")

            start_bg(
                hdst,
                f"timeout {duration} tcpdump -i {shlex.quote(rx_iface)} -n -U -s 0 -w {shlex.quote(rx_pcap)}",
                tcpdump_pid, tcpdump_log
            )
            time.sleep(0.6)

            import sys
            cmd = (
                f"{shlex.quote(sys.executable)} {shlex.quote(gen_script)} "
                f"--legit {shlex.quote(pcap_legit)} "
                f"--mal {shlex.quote(pcap_malign)} "
                f"--duration {duration} "
                f"--burst-ms {GEN_BURST_MS} "
                f"--p-mal {GEN_P_MAL} "
                f"--rate {int(pps)} "
                f"--batch {GEN_BATCH} "
                f"--iface {shlex.quote(tx_iface)} "
                f"--src-mac {src_mac} "
                f"--dst-mac {dst_mac} "
                f"--dst-ip {shlex.quote(hdst_ip)} "
                f"--seed {GEN_SEED}"
            )
            out = run_cmd(hsrc, f"{cmd} 2>&1 | tee {shlex.quote(gen_log)}")
            time.sleep(1.0)

            tx = parse_gen_stdout(out, duration)
            tx_total = tx["tx_total"]

            stop_bg(hdst, tcpdump_pid)

            rx_pkts = count_pcap_packets(hdst, rx_pcap)
            pps_measured = (rx_pkts / float(duration)) if duration > 0 else 0.0
            lost = max(0, tx_total - rx_pkts)
            loss_percent = (lost / tx_total * 100.0) if tx_total > 0 else 0.0
            note = "" if tx_total > 0 else "gen_sent_0 (ver gen log)"

            row = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "xdp": xdp_label,
                "label": "trafico_eth",
                "pps_target": pps,
                "pps_measured": f"{pps_measured:.2f}",
                "lost_percent": f"{loss_percent:.2f}",
                "lost_packets": lost,
                "packets_total": rx_pkts,
                "tx_packets_total": tx_total,
                "tx_legit_packets": tx["tx_legit"],
                "tx_mal_packets": tx["tx_mal"],
                "note": note,
            }

            write_header = not os.path.exists(csv_path)
            with open(csv_path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=header)
                if write_header:
                    w.writeheader()
                w.writerow(row)

            time.sleep(sleep_between_runs)

    print("[GEN] sin XDP")
    run_block("off")
    time.sleep(sleep_between_blocks)

    xdp_pid = os.path.join(base_dir, "xdp_usr_trafico_eth.pid")
    xdp_log = os.path.join(base_dir, "xdp_usr_trafico_eth.log")
    print(f"[GEN] Activando XDP en {rx_iface} (trafico_eth)")
    start_xdp(hdst, repo_root, rx_iface, xdp_pid, xdp_log)
    try:
        print("[GEN] con XDP")
        run_block("on")
    finally:
        print("[GEN] Desactivando XDP (trafico_eth)")
        stop_bg(hdst, xdp_pid)


# ======================================================
# MAIN
# ======================================================

def main():
    if os.geteuid() != 0:
        raise SystemExit("Este script debe ejecutarse como root (sudo).")

    ap = argparse.ArgumentParser(description="Suite Mininet v12 (sin tcprewrite, tcpreplay limitado, generator path fix)")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("-l", "--legit", dest="pcap_legit", required=True,
                    help="PCAP legit ya prewritten para Mininet (recomendado)")
    ap.add_argument("-m", "--malign", dest="pcap_malign", required=True,
                    help="PCAP malign ya prewritten para Mininet (recomendado)")
    ap.add_argument("--skip-iperf", action="store_true")
    ap.add_argument("--skip-tcpreplay", action="store_true")
    ap.add_argument("--skip-generator", action="store_true")
    ap.add_argument("--quick", action="store_true", help="Reduce duraciones y sleeps para depurar rápido")
    args = ap.parse_args()

    repo_root = args.repo_root

    # Resolver rutas absolutas para consistencia
    pcap_legit = abspath(repo_root, args.pcap_legit)
    pcap_malign = abspath(repo_root, args.pcap_malign)

    must_exist_file(pcap_legit, "PCAP legit")
    must_exist_file(pcap_malign, "PCAP malign")

    # Parámetros runtime
    pps_steps = PPS_STEPS_DEFAULT
    iperf_duration = 10
    tcpreplay_duration = TCPREPLAY_DURATION_DEFAULT
    gen_duration = GEN_DURATION_DEFAULT
    sleep_runs = SLEEP_BETWEEN_RUNS_DEFAULT
    sleep_blocks = SLEEP_BETWEEN_BLOCKS_DEFAULT
    sleep_exp = SLEEP_BETWEEN_EXPERIMENTS_DEFAULT

    if args.quick:
        pps_steps = [64, 128]
        iperf_duration = 3
        tcpreplay_duration = 3
        gen_duration = 3.0
        sleep_runs = 0.5
        sleep_blocks = 1.0
        sleep_exp = 1.0

    suite_dir = f"/tmp/exp_suite_{now_tag()}"
    os.makedirs(suite_dir, exist_ok=True)
    iperf_dir = os.path.join(suite_dir, "iperf")
    tcpr_dir = os.path.join(suite_dir, "tcpreplay")
    gen_dir = os.path.join(suite_dir, "generator")
    os.makedirs(iperf_dir, exist_ok=True)
    os.makedirs(tcpr_dir, exist_ok=True)
    os.makedirs(gen_dir, exist_ok=True)

    net = Mininet(topo=SimpleTopo(), controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=False)
    net.start()
    try:
        print(f"[INFO] Mininet iniciado. Resultados en {suite_dir}")
        preflight(net, suite_dir)

        if not args.skip_iperf:
            print("[INFO] ====== FASE 1: IPERF ======")
            iperf_sweep(net, iperf_dir, repo_root, pps_steps, iperf_duration, sleep_runs, sleep_blocks)
            time.sleep(sleep_exp)

        if not args.skip_tcpreplay:
            print("[INFO] ====== FASE 2: TCPREPLAY (legit/malign) ======")
            tcpreplay_sweep(net, tcpr_dir, repo_root, pcap_legit, "legit", pps_steps, tcpreplay_duration, sleep_runs, sleep_blocks)
            time.sleep(sleep_exp)
            tcpreplay_sweep(net, tcpr_dir, repo_root, pcap_malign, "malign", pps_steps, tcpreplay_duration, sleep_runs, sleep_blocks)
            time.sleep(sleep_exp)

        if not args.skip_generator:
            print("[INFO] ====== FASE 3: TRAFICO_ETH ======")
            trafico_eth_sweep(net, gen_dir, repo_root, pcap_legit, pcap_malign, pps_steps, gen_duration, sleep_runs, sleep_blocks)

    finally:
        net.stop()
        print(f"[INFO] Fin. Resultados en {suite_dir}")


if __name__ == "__main__":
    setLogLevel("info")
    main()
