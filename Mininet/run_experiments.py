#!/usr/bin/env python3
import argparse
import csv
import json
import os
import shlex
import time
from datetime import datetime

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

from redarbolrw1 import SimpleTopo


# ======================================================
# CONFIGURACIÓN EXPERIMENTAL FIJA (UNA SOLA VERDAD)
# ======================================================

PPS_STEPS = [5000, 10000, 20000, 40000, 80000, 160000]

# iperf
IPERF_DURATION = 10          # segundos
IPERF_PAYLOAD_LEN = 1400     # bytes
IPERF_SERVER_PORT = 5201

# tcpreplay
TCPREPLAY_DURATION = 10      # segundos

# tu generador (trafico_eth.py)
GEN_DURATION = 10.0          # segundos
GEN_BURST_MS = 200           # ms
GEN_P_MAL = 0.5
GEN_BATCH = 64
GEN_SEED = 12345             # reproducible

# sleeps
SLEEP_BETWEEN_RUNS = 2.0
SLEEP_BETWEEN_BLOCKS = 8.0
SLEEP_BETWEEN_EXPERIMENTS = 10.0   # entre iperf/tcpreplay/generador

# XDP (modelo real con xdp_usr)
XDP_USR_REL_PATH = "XDP/arbol_prueba/xdp_usr"
XDP_INTERFACE = "hdst-eth0"

HDST_IP = "10.0.1.2"

# Preferencias de interfaces (pero auto-detectamos si no existen en el namespace)
PREFERRED_TX_IFACE = "hsrc-eth0"
PREFERRED_RX_IFACE = "hdst-eth0"

# MACs fijas en SimpleTopo() (las que ya usas en CLI)
SRC_MAC = "00:00:00:00:01:01"
DST_MAC = "00:00:00:00:02:02"

# Ruta al script del generador (relativa al repo-root)
# En tu traceback estaba en .../TFG_Informatica/Mininet/trafico_eth.py
GEN_SCRIPT_REL_PATH = "Mininet/trafico_eth.py"


# ======================================================
# UTILIDADES
# ======================================================

def now_tag():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(host, path):
    host.cmd(f"mkdir -p {shlex.quote(path)}")


def run_cmd(host, cmd):
    return host.cmd(cmd)


def start_bg(host, cmd, pidfile, logfile):
    host.cmd(
        f"{cmd} > {shlex.quote(logfile)} 2>&1 & "
        f"echo $! > {shlex.quote(pidfile)}"
    )


def stop_bg(host, pidfile):
    host.cmd(f"kill $(cat {shlex.quote(pidfile)}) >/dev/null 2>&1 || true")


def ping_sanity(net):
    # rellena ARP (útil también para tcpdump/otros)
    print(net["hsrc"].cmd(f"ping -c 1 {HDST_IP}"))


def pps_to_bitrate_bps(pps, payload_bytes):
    return pps * payload_bytes * 8


def abspath(repo_root: str, path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(repo_root, path)


def list_ifaces(host) -> list[str]:
    out = host.cmd("ip -o link show | awk -F': ' '{print $2}'")
    return [x.strip() for x in out.splitlines() if x.strip()]


def pick_iface(host, preferred: str) -> str:
    # En Mininet, a veces dentro del namespace la iface se llama eth0.
    # Preferimos hsrc-eth0/hdst-eth0, pero si no existe usamos eth0 o la primera no-lo.
    ifaces = list_ifaces(host)
    if preferred in ifaces:
        return preferred
    if "eth0" in ifaces:
        return "eth0"
    for i in ifaces:
        if i != "lo":
            return i
    return preferred  # último recurso


def count_pcap_packets(host, pcap_path: str) -> int:
    out = host.cmd(f"tcpdump -n -r {shlex.quote(pcap_path)} 2>/dev/null | wc -l")
    try:
        return int(out.strip())
    except Exception:
        return 0


def start_xdp(hdst, repo_root, pid_path, log_path):
    xdp_bin = os.path.join(repo_root, XDP_USR_REL_PATH)
    run_cmd(hdst, f"chmod +x {shlex.quote(xdp_bin)}")
    start_bg(hdst, f"{shlex.quote(xdp_bin)} {shlex.quote(XDP_INTERFACE)}", pid_path, log_path)


# ======================================================
# IPERF
# ======================================================

def parse_iperf_json(j):
    end = j.get("end", {})
    s = end.get("sum", {}) or end.get("sum_received", {}) or {}

    packets = int(s.get("packets", 0))
    lost_packets = int(s.get("lost_packets", 0))
    lost_percent = float(s.get("lost_percent", 0.0))
    bps = float(s.get("bits_per_second", 0.0))
    measured_pps = packets / IPERF_DURATION if IPERF_DURATION > 0 else 0.0

    return {
        "packets": packets,
        "lost_packets": lost_packets,
        "lost_percent": lost_percent,
        "bps": bps,
        "pps": measured_pps,
    }


def iperf_sweep(net, results_dir, repo_root):
    hsrc, hdst = net["hsrc"], net["hdst"]
    ensure_dir(hdst, results_dir)

    csv_path = os.path.join(results_dir, "iperf_results.csv")

    header = [
        "timestamp",
        "xdp",
        "pps_target",
        "pps_measured",
        "bps_measured",
        "lost_percent",
        "lost_packets",
        "packets_total",
    ]

    def run_block(xdp_label):
        for pps in PPS_STEPS:
            print(f"[INFO] IPERF | XDP={xdp_label} | Ejecutando PPS objetivo = {pps}")
            bitrate = pps_to_bitrate_bps(pps, IPERF_PAYLOAD_LEN)

            tag = f"{xdp_label}_pps{pps}_{now_tag()}"
            srv_log = os.path.join(results_dir, f"iperf_srv_{tag}.log")
            srv_pid = os.path.join(results_dir, f"iperf_srv_{tag}.pid")
            cli_json = os.path.join(results_dir, f"iperf_cli_{tag}.json")

            start_bg(
                hdst,
                f"iperf3 -s -p {IPERF_SERVER_PORT}",
                srv_pid,
                srv_log,
            )
            time.sleep(0.3)

            cmd = (
                f"iperf3 -c {HDST_IP} "
                f"-p {IPERF_SERVER_PORT} "
                f"-u -t {IPERF_DURATION} "
                f"-l {IPERF_PAYLOAD_LEN} "
                f"-b {bitrate} "
                f"-J"
            )

            out = run_cmd(hsrc, cmd)
            stop_bg(hdst, srv_pid)

            try:
                j = json.loads(out)
                with open(cli_json, "w") as f:
                    json.dump(j, f, indent=2)
                m = parse_iperf_json(j)
            except Exception:
                m = {"packets": 0, "lost_packets": 0, "lost_percent": 0.0, "bps": 0.0, "pps": 0.0}

            row = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "xdp": xdp_label,
                "pps_target": pps,
                "pps_measured": f"{m['pps']:.2f}",
                "bps_measured": f"{m['bps']:.2f}",
                "lost_percent": f"{m['lost_percent']:.2f}",
                "lost_packets": m["lost_packets"],
                "packets_total": m["packets"],
            }

            write_header = not os.path.exists(csv_path)
            with open(csv_path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=header)
                if write_header:
                    w.writeheader()
                w.writerow(row)

            time.sleep(SLEEP_BETWEEN_RUNS)

    print("[INFO] Iniciando pruebas iperf SIN XDP")
    run_block("off")

    time.sleep(SLEEP_BETWEEN_BLOCKS)

    xdp_pid = os.path.join(results_dir, "xdp_usr.pid")
    xdp_log = os.path.join(results_dir, "xdp_usr.log")

    print("[INFO] Activando XDP (xdp_usr) para iperf")
    start_xdp(hdst, repo_root, xdp_pid, xdp_log)
    print("[INFO] XDP activo")

    try:
        print("[INFO] Iniciando pruebas iperf CON XDP")
        run_block("on")
    finally:
        print("[INFO] Desactivando XDP (kill xdp_usr) para iperf")
        stop_bg(hdst, xdp_pid)
        print("[INFO] XDP desactivado")


# ======================================================
# TCPREPLAY (2 PCAPs: legit/malign; 2 CSVs)
# ======================================================

def tcpreplay_sweep(net, results_dir: str, repo_root: str, pcap_path: str, label: str):
    hsrc, hdst = net["hsrc"], net["hdst"]
    ensure_dir(hdst, results_dir)

    base_dir = os.path.join(results_dir, label)
    pcaps_dir = os.path.join(base_dir, "pcaps")
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(pcaps_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    csv_path = os.path.join(base_dir, f"tcpreplay_{label}_results.csv")

    header = [
        "timestamp",
        "xdp",
        "label",
        "pps_target",
        "pps_measured",
        "bps_measured",
        "lost_percent",
        "lost_packets",
        "packets_total",
    ]

    pcap_in = abspath(repo_root, pcap_path)

    tx_iface = pick_iface(hsrc, PREFERRED_TX_IFACE)
    rx_iface = pick_iface(hdst, PREFERRED_RX_IFACE)

    print(f"[INFO] TCPREPLAY({label}) usando ifaces: TX={tx_iface}  RX={rx_iface}")

    def run_block(xdp_label: str):
        for pps in PPS_STEPS:
            print(f"[INFO] TCPREPLAY({label}) | XDP={xdp_label} | Ejecutando PPS objetivo = {pps}")

            tag = f"{label}_{xdp_label}_pps{pps}_{now_tag()}"
            pcap_out = os.path.join(pcaps_dir, f"rx_{tag}.pcap")

            tcpdump_log = os.path.join(logs_dir, f"tcpdump_{tag}.log")
            tcpdump_pid = os.path.join(logs_dir, f"tcpdump_{tag}.pid")
            tcpreplay_log = os.path.join(logs_dir, f"tcpreplay_{tag}.log")

            start_bg(
                hdst,
                f"timeout {TCPREPLAY_DURATION} tcpdump -i {shlex.quote(rx_iface)} -n -U -s 0 -w {shlex.quote(pcap_out)}",
                tcpdump_pid,
                tcpdump_log,
            )
            time.sleep(0.5)

            run_cmd(
                hsrc,
                f"tcpreplay --intf1={shlex.quote(tx_iface)} --pps={int(pps)} {shlex.quote(pcap_in)} > {shlex.quote(tcpreplay_log)} 2>&1"
            )
            time.sleep(0.5)

            rx_pkts = count_pcap_packets(hdst, pcap_out)
            pps_measured = (rx_pkts / TCPREPLAY_DURATION) if TCPREPLAY_DURATION > 0 else 0.0

            expected_pkts = int(round(TCPREPLAY_DURATION * pps))
            lost_packets = expected_pkts - rx_pkts
            if lost_packets < 0:
                lost_packets = 0

            loss_percent = (lost_packets / expected_pkts * 100.0) if expected_pkts > 0 else 0.0
            bps_measured = 0.0

            row = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "xdp": xdp_label,
                "label": label,
                "pps_target": pps,
                "pps_measured": f"{pps_measured:.2f}",
                "bps_measured": f"{bps_measured:.2f}",
                "lost_percent": f"{loss_percent:.2f}",
                "lost_packets": lost_packets,
                "packets_total": rx_pkts,
            }

            write_header = not os.path.exists(csv_path)
            with open(csv_path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=header)
                if write_header:
                    w.writeheader()
                w.writerow(row)

            time.sleep(SLEEP_BETWEEN_RUNS)

    print(f"[INFO] Iniciando pruebas tcpreplay({label}) SIN XDP")
    run_block("off")

    time.sleep(SLEEP_BETWEEN_BLOCKS)

    xdp_pid = os.path.join(base_dir, f"xdp_usr_tcpreplay_{label}.pid")
    xdp_log = os.path.join(base_dir, f"xdp_usr_tcpreplay_{label}.log")

    print(f"[INFO] Activando XDP (xdp_usr) para tcpreplay({label})")
    start_xdp(hdst, repo_root, xdp_pid, xdp_log)
    print("[INFO] XDP activo")

    try:
        print(f"[INFO] Iniciando pruebas tcpreplay({label}) CON XDP")
        run_block("on")
    finally:
        print(f"[INFO] Desactivando XDP (kill xdp_usr) para tcpreplay({label})")
        stop_bg(hdst, xdp_pid)
        print("[INFO] XDP desactivado")


# ======================================================
# TU SCRIPT (trafico_eth.py) — OFF/ON, y CSV global
# ======================================================

def trafico_eth_sweep(net, results_dir: str, repo_root: str, pcap_legit: str, pcap_malign: str):
    hsrc, hdst = net["hsrc"], net["hdst"]
    ensure_dir(hdst, results_dir)

    base_dir = os.path.join(results_dir, "trafico_eth")
    pcaps_dir = os.path.join(base_dir, "pcaps")
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(pcaps_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    csv_path = os.path.join(base_dir, "trafico_eth_results.csv")

    header = [
        "timestamp",
        "xdp",
        "label",
        "pps_target",
        "pps_measured",
        "bps_measured",
        "lost_percent",
        "lost_packets",
        "packets_total",
        "tx_packets_target",
    ]

    gen_script = abspath(repo_root, GEN_SCRIPT_REL_PATH)
    legit_abs = abspath(repo_root, pcap_legit)
    mal_abs = abspath(repo_root, pcap_malign)

    tx_iface = pick_iface(hsrc, PREFERRED_TX_IFACE)
    rx_iface = pick_iface(hdst, PREFERRED_RX_IFACE)

    print(f"[INFO] TRAFICO_ETH usando ifaces: TX={tx_iface}  RX={rx_iface}")
    print(f"[INFO] TRAFICO_ETH usando script: {gen_script}")

    def run_block(xdp_label: str):
        for pps in PPS_STEPS:
            print(f"[INFO] TRAFICO_ETH | XDP={xdp_label} | Ejecutando PPS objetivo = {pps}")

            tag = f"{xdp_label}_pps{pps}_{now_tag()}"
            pcap_out = os.path.join(pcaps_dir, f"rx_{tag}.pcap")

            tcpdump_log = os.path.join(logs_dir, f"tcpdump_{tag}.log")
            tcpdump_pid = os.path.join(logs_dir, f"tcpdump_{tag}.pid")
            gen_log = os.path.join(logs_dir, f"gen_{tag}.log")

            start_bg(
                hdst,
                f"timeout {GEN_DURATION} tcpdump -i {shlex.quote(rx_iface)} -n -U -s 0 -w {shlex.quote(pcap_out)}",
                tcpdump_pid,
                tcpdump_log,
            )
            time.sleep(0.5)

            cmd = (
                f"python3 {shlex.quote(gen_script)} "
                f"--legit {shlex.quote(legit_abs)} "
                f"--mal {shlex.quote(mal_abs)} "
                f"--duration {GEN_DURATION} "
                f"--burst-ms {GEN_BURST_MS} "
                f"--p-mal {GEN_P_MAL} "
                f"--rate {int(pps)} "
                f"--batch {GEN_BATCH} "
                f"--iface {shlex.quote(tx_iface)} "
                f"--src-mac {shlex.quote(SRC_MAC)} "
                f"--dst-mac {shlex.quote(DST_MAC)} "
                f"--dst-ip {shlex.quote(HDST_IP)} "
                f"--seed {GEN_SEED}"
            )

            run_cmd(hsrc, f"{cmd} 2>&1 | tee {shlex.quote(gen_log)}")
            time.sleep(0.5)

            rx_pkts = count_pcap_packets(hdst, pcap_out)
            pps_measured = (rx_pkts / float(GEN_DURATION)) if GEN_DURATION > 0 else 0.0

            tx_target = int(round(float(GEN_DURATION) * int(pps)))
            lost_packets = tx_target - rx_pkts
            if lost_packets < 0:
                lost_packets = 0
            loss_percent = (lost_packets / tx_target * 100.0) if tx_target > 0 else 0.0

            row = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "xdp": xdp_label,
                "label": "trafico_eth",
                "pps_target": pps,
                "pps_measured": f"{pps_measured:.2f}",
                "bps_measured": f"{0.0:.2f}",
                "lost_percent": f"{loss_percent:.2f}",
                "lost_packets": lost_packets,
                "packets_total": rx_pkts,
                "tx_packets_target": tx_target,
            }

            write_header = not os.path.exists(csv_path)
            with open(csv_path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=header)
                if write_header:
                    w.writeheader()
                w.writerow(row)

            time.sleep(SLEEP_BETWEEN_RUNS)

    print("[INFO] Iniciando pruebas trafico_eth SIN XDP")
    run_block("off")

    time.sleep(SLEEP_BETWEEN_BLOCKS)

    xdp_pid = os.path.join(base_dir, "xdp_usr_trafico_eth.pid")
    xdp_log = os.path.join(base_dir, "xdp_usr_trafico_eth.log")

    print("[INFO] Activando XDP (xdp_usr) para trafico_eth")
    start_xdp(hdst, repo_root, xdp_pid, xdp_log)
    print("[INFO] XDP activo")

    try:
        print("[INFO] Iniciando pruebas trafico_eth CON XDP")
        run_block("on")
    finally:
        print("[INFO] Desactivando XDP (kill xdp_usr) para trafico_eth")
        stop_bg(hdst, xdp_pid)
        print("[INFO] XDP desactivado")


# ======================================================
# MAIN (Suite completa)
# ======================================================

def main():
    if os.geteuid() != 0:
        raise SystemExit("Este script debe ejecutarse como root (sudo).")

    ap = argparse.ArgumentParser(
        description="Suite Mininet: iperf -> tcpreplay (legit/malign) -> trafico_eth.py"
    )
    ap.add_argument("--repo-root", required=True, help="Ruta absoluta al root del repo")
    ap.add_argument("-l", "--legit", dest="pcap_legit", default=None,
                    help="PCAP legítimo (ruta absoluta o relativa a repo-root)")
    ap.add_argument("-m", "--malign", dest="pcap_malign", default=None,
                    help="PCAP maligno (ruta absoluta o relativa a repo-root)")

    args = ap.parse_args()

    suite_dir = f"/tmp/exp_suite_{now_tag()}"
    iperf_dir = os.path.join(suite_dir, "iperf")
    tcpr_dir = os.path.join(suite_dir, "tcpreplay")
    gen_dir = os.path.join(suite_dir, "generator")
    os.makedirs(iperf_dir, exist_ok=True)
    os.makedirs(tcpr_dir, exist_ok=True)
    os.makedirs(gen_dir, exist_ok=True)

    net = Mininet(
        topo=SimpleTopo(),
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False,
    )

    net.start()
    try:
        print("[INFO] Mininet arrancado correctamente")
        ping_sanity(net)

        print(f"[INFO] Suite resultados en: {suite_dir}")

        print("[INFO] ====== FASE 1: IPERF ======")
        iperf_sweep(net, iperf_dir, args.repo_root)

        if args.pcap_legit or args.pcap_malign:
            print("[INFO] Esperando entre fases para limpiar estado…")
            time.sleep(SLEEP_BETWEEN_EXPERIMENTS)

            print("[INFO] ====== FASE 2: TCPREPLAY ======")
            if args.pcap_legit:
                tcpreplay_sweep(net, tcpr_dir, args.repo_root, args.pcap_legit, label="legit")
                time.sleep(SLEEP_BETWEEN_EXPERIMENTS)
            if args.pcap_malign:
                tcpreplay_sweep(net, tcpr_dir, args.repo_root, args.pcap_malign, label="malign")
                time.sleep(SLEEP_BETWEEN_EXPERIMENTS)

            if args.pcap_legit and args.pcap_malign:
                print("[INFO] ====== FASE 3: TRAFICO_ETH (tu script) ======")
                trafico_eth_sweep(net, gen_dir, args.repo_root, args.pcap_legit, args.pcap_malign)
            else:
                print("[INFO] (FASE 3 omitida) trafico_eth necesita -l y -m a la vez.")
        else:
            print("[INFO] No se pasaron PCAPs (-l/-m): se omiten tcpreplay y trafico_eth (solo iperf).")

    finally:
        net.stop()
        print(f"[INFO] Resultados en: {suite_dir}")


if __name__ == "__main__":
    setLogLevel("info")
    main()
