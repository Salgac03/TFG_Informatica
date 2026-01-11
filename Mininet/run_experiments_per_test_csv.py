#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import shlex
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

# Importa TU topología sin duplicarla
from redarbolrw1 import SimpleTopo


# -----------------------------
# Utilidades generales
# -----------------------------
def abspath(repo_root: str, path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(repo_root, path)


def now_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def per_test_csv(results_dir: str, tool: str, run_tag: str) -> str:
    """Ruta del CSV homogeneizado para un test concreto."""
    safe_tool = re.sub(r"[^a-zA-Z0-9_-]+", "_", tool)
    ensure_dir_local(results_dir)
    return os.path.join(results_dir, f"{safe_tool}_results_{run_tag}.csv")


def ensure_dir(host, path: str):
    host.cmd(f"mkdir -p {shlex.quote(path)}")


def ensure_dir_local(path: str):
    os.makedirs(path, exist_ok=True)


def run_cmd(host, cmd: str, log_path: str | None = None) -> str:
    """
    Ejecuta cmd en el host (namespace Mininet). Si log_path se pasa, redirige stdout/stderr ahí.
    Devuelve stdout (si no rediriges) o string vacío (si rediriges).
    """
    if log_path:
        return host.cmd(f"{cmd} > {shlex.quote(log_path)} 2>&1")
    return host.cmd(cmd)


def start_bg(host, cmd: str, pidfile: str, log_path: str):
    """
    Lanza cmd en background en el host, guarda PID en pidfile, log a log_path.
    """
    qpid = shlex.quote(pidfile)
    qlog = shlex.quote(log_path)
    host.cmd(f"{cmd} > {qlog} 2>&1 & echo $! > {qpid}")


def stop_bg(host, pidfile: str):
    host.cmd(f"kill $(cat {shlex.quote(pidfile)}) >/dev/null 2>&1 || true")


def ping_sanity(net):
    out = net["hsrc"].cmd("ping -c 1 10.0.1.2")
    print(out)


# -----------------------------
# Normalización de resultados a CSVs homogéneos (uno por test)
# -----------------------------
NORMALIZED_COLUMNS = [
    # Identificación
    "run_tag",
    "mode",
    "tool",
    "timestamp_utc",
    # Contexto
    "src",
    "dst",
    "protocol",
    "direction",
    "duration_s",
    "notes",
    # Intervalo (si aplica)
    "interval_start_s",
    "interval_end_s",
    # Métricas comunes
    "throughput_bps",
    "tx_bytes",
    "rx_bytes",
    "tx_pps",
    "rx_pps",
    "lost_packets",
    "loss_percent",
    "retransmits",
    # Parámetros específicos (vacíos si no aplica)
    "parallel",
    "udp_bitrate",
    "pcap",
    "pps_target",
]


class NormalizedCSVWriter:
    def __init__(self, out_csv: str):
        self.out_csv = out_csv
        self._initialized = os.path.exists(out_csv) and os.path.getsize(out_csv) > 0
        ensure_dir_local(os.path.dirname(out_csv))

    def append_rows(self, rows: Iterable[Dict[str, Any]]):
        mode = "a" if self._initialized else "w"
        with open(self.out_csv, mode, newline="") as f:
            w = csv.DictWriter(f, fieldnames=NORMALIZED_COLUMNS, extrasaction="ignore")
            if not self._initialized:
                w.writeheader()
                self._initialized = True
            for r in rows:
                # Completa columnas ausentes con vacío
                full = {k: "" for k in NORMALIZED_COLUMNS}
                full.update(r)
                w.writerow(full)


def _utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _safe_float(x: Any) -> Optional[float]:
    try:
        if x is None or x == "":
            return None
        return float(x)
    except Exception:
        return None


def _pick_iperf_interval_sums(interval: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Devuelve (sent_sum, recv_sum) para un intervalo. iperf3 JSON puede variar según modo.
    """
    # TCP típico
    sent = interval.get("sum_sent") or interval.get("sum") or {}
    recv = interval.get("sum_received") or {}
    # UDP típico: sum suele ser el lado emisor, sum_received el receptor
    if not recv and "sum" in interval and "sum_received" in interval:
        recv = interval.get("sum_received") or {}
    return sent, recv


def normalize_iperf_json_to_rows(
    json_path: str,
    run_tag: str,
    duration: int,
    parallel: int,
    reverse: bool,
    udp: bool,
    bitrate: Optional[str],
    src: str = "hsrc",
    dst: str = "hdst",
) -> List[Dict[str, Any]]:
    """
    Convierte iperf3 JSON a filas normalizadas (una por intervalo).
    - throughput_bps: en TCP, preferimos recv_bps (goodput recibido). En UDP, recv_bps.
    - tx_bytes/rx_bytes: bytes del intervalo (sent/received).
    """
    with open(json_path, "r") as f:
        data = json.load(f)

    rows: List[Dict[str, Any]] = []
    protocol = "udp" if udp else "tcp"
    direction = "reverse" if reverse else "forward"

    intervals = data.get("intervals", [])
    for it in intervals:
        sent, recv = _pick_iperf_interval_sums(it)

        start_s = it.get("start")
        end_s = it.get("end")

        sent_bps = sent.get("bits_per_second")
        recv_bps = recv.get("bits_per_second")

        # Para comparabilidad con tcpreplay, guardamos throughput del receptor siempre que exista
        throughput = recv_bps if recv_bps is not None else sent_bps

        row = {
            "run_tag": run_tag,
            "mode": "iperf",
            "tool": "iperf3",
            "timestamp_utc": _utc_now_iso(),
            "src": src,
            "dst": dst,
            "protocol": protocol,
            "direction": direction,
            "duration_s": duration,
            "interval_start_s": start_s,
            "interval_end_s": end_s,
            "throughput_bps": throughput,
            "tx_bytes": sent.get("bytes", ""),
            "rx_bytes": recv.get("bytes", ""),
            "retransmits": sent.get("retransmits", "") or recv.get("retransmits", ""),
            "loss_percent": recv.get("lost_percent", "") if udp else "",
            "lost_packets": recv.get("lost_packets", "") if udp else "",
            "parallel": parallel if parallel else 1,
            "udp_bitrate": bitrate if udp else "",
            "notes": "",
        }
        rows.append(row)

    # Fila resumen "total" (opcional, útil para tablas en TFG)
    end = data.get("end", {})
    sum_sent = end.get("sum_sent") or end.get("sum") or {}
    sum_recv = end.get("sum_received") or {}
    if sum_sent or sum_recv:
        throughput = sum_recv.get("bits_per_second") if sum_recv else sum_sent.get("bits_per_second")
        rows.append(
            {
                "run_tag": run_tag,
                "mode": "iperf",
                "tool": "iperf3",
                "timestamp_utc": _utc_now_iso(),
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "direction": direction,
                "duration_s": duration,
                "interval_start_s": "",
                "interval_end_s": "",
                "throughput_bps": throughput,
                "tx_bytes": sum_sent.get("bytes", ""),
                "rx_bytes": sum_recv.get("bytes", ""),
                "retransmits": sum_sent.get("retransmits", "") or sum_recv.get("retransmits", ""),
                "loss_percent": (sum_recv.get("lost_percent", "") if udp else ""),
                "lost_packets": (sum_recv.get("lost_packets", "") if udp else ""),
                "parallel": parallel if parallel else 1,
                "udp_bitrate": bitrate if udp else "",
                "notes": "TOTAL",
            }
        )

    return rows


def normalize_generic_csvs(results_dir: str, run_tag: str, mode: str, tool: str) -> List[Dict[str, Any]]:
    """
    Intenta normalizar CSVs generados por scripts externos (tcpreplay / custom si generan CSV).
    Estrategia:
      - Busca CSVs en results_dir que contengan run_tag o mode en nombre.
      - Lee header y mapea campos comunes si existen.
    Como no conocemos los headers exactos de rx_capture_server.sh, hacemos un mapeo flexible.
    """
    rows: List[Dict[str, Any]] = []

    # heurística: todos los CSV en results_dir excepto el normalized
    for fn in os.listdir(results_dir):
        if not fn.lower().endswith(".csv"):
            continue
        if fn == "normalized_results.csv":
            continue

        path = os.path.join(results_dir, fn)
        try:
            with open(path, newline="") as f:
                reader = csv.DictReader(f)
                header = [h.strip() for h in (reader.fieldnames or [])]
                if not header:
                    continue

                # Mapeos comunes (añade aquí si tus scripts usan otros nombres)
                keymap = {
                    "interval_start_s": ["start", "start_s", "t_start", "interval_start", "interval_start_s"],
                    "interval_end_s": ["end", "end_s", "t_end", "interval_end", "interval_end_s"],
                    "tx_pps": ["tx_pps", "pps_tx", "sent_pps", "pps_sent"],
                    "rx_pps": ["rx_pps", "pps_rx", "recv_pps", "pps_recv", "received_pps"],
                    "tx_bytes": ["tx_bytes", "bytes_tx", "sent_bytes", "bytes_sent"],
                    "rx_bytes": ["rx_bytes", "bytes_rx", "recv_bytes", "bytes_recv", "received_bytes"],
                    "loss_percent": ["loss_percent", "lost_percent", "loss_pct", "drop_pct"],
                    "lost_packets": ["lost_packets", "dropped", "drops", "lost"],
                    "throughput_bps": ["throughput_bps", "bps", "rate_bps", "goodput_bps"],
                    "pps_target": ["pps_target", "target_pps", "pps"],
                }

                def pick(d: Dict[str, Any], candidates: List[str]) -> Any:
                    for c in candidates:
                        if c in d and d[c] != "":
                            return d[c]
                    return ""

                for d in reader:
                    r = {
                        "run_tag": run_tag,
                        "mode": mode,
                        "tool": tool,
                        "timestamp_utc": _utc_now_iso(),
                        "src": "hsrc",
                        "dst": "hdst",
                        "protocol": "",
                        "direction": "",
                        "duration_s": "",
                        "notes": f"from:{fn}",
                    }
                    for outk, cands in keymap.items():
                        r[outk] = pick(d, cands)
                    rows.append(r)
        except Exception:
            # si un CSV es raro/no parseable, lo ignoramos para no romper el runner
            continue

    return rows


# -----------------------------
# Tests
# -----------------------------
def tcpreplay_test(net, repo_root, pcap, duration, ctrl_port, prefix, reps, results_dir, run_tag: str):
    out_csv = per_test_csv(results_dir, "tcpreplay", run_tag)
    norm = NormalizedCSVWriter(out_csv)
    scripts_dir = os.path.join(repo_root, "Pruebas", "nuevas_pruebas")
    rx_script = os.path.join(scripts_dir, "rx_capture_server.sh")
    runner_script = os.path.join(scripts_dir, "run_tcpreplay_pps.sh")

    hsrc, hdst = net["hsrc"], net["hdst"]
    ensure_dir(hdst, results_dir)
    ensure_dir(hsrc, results_dir)

    # Receptor tcpdump (escucha control + captura)
    rx_log = os.path.join(results_dir, f"rx_capture_{prefix}_{run_tag}.log")
    rx_pid = os.path.join(results_dir, "rx_capture.pid")

    # rx_capture_server escribe CSVs en el OUT_DIR (results_dir)
    start_bg(
        hdst,
        f"chmod +x {shlex.quote(rx_script)} {shlex.quote(runner_script)} >/dev/null 2>&1 || true; "
        f"{shlex.quote(rx_script)} hdst-eth0 {shlex.quote(results_dir)} {ctrl_port}",
        rx_pid,
        rx_log,
    )
    time.sleep(0.5)

    # Runner en hsrc (barre PPS y manda START al receptor)
    runner_log = os.path.join(results_dir, f"runner_{prefix}_{run_tag}.log")
    pcap_abs = abspath(repo_root, pcap)
    cmd_runner = (
        f"chmod +x {shlex.quote(runner_script)} >/dev/null 2>&1 || true; "
        f"{shlex.quote(runner_script)} hsrc-eth0 {shlex.quote(pcap_abs)} {duration} 10.0.1.2 {ctrl_port} "
        f"{shlex.quote(prefix)} {reps}"
    )
    run_cmd(hsrc, cmd_runner, runner_log)

    # Parar receptor
    stop_bg(hdst, rx_pid)

    # Normaliza lo que haya generado rx_capture_server.sh (flexible)
    rows = normalize_generic_csvs(results_dir, run_tag=run_tag, mode="tcpreplay", tool="tcpreplay")
    if rows:
        norm.append_rows(rows)

    print(f"[OK] TCPReplay: CSVs/logs en {results_dir} | Normalizado -> {norm.out_csv}")


def iperf_test(net, results_dir, duration, parallel, reverse, udp, bitrate, run_tag: str):
    """
    iperf3 con salida JSON + normalización a CSV común.

    Cambio importante:
      - Ya NO generamos un CSV 'propio' diferente para iperf. Generamos un JSON (como antes) y volcamos
        sus métricas al CSV normalizado (misma estructura que el resto de pruebas).
    """
    out_csv = per_test_csv(results_dir, "iperf3", run_tag)
    norm = NormalizedCSVWriter(out_csv)
    hsrc, hdst = net["hsrc"], net["hdst"]
    ensure_dir(hdst, results_dir)
    ensure_dir(hsrc, results_dir)

    srv_log = os.path.join(results_dir, f"iperf3_server_{run_tag}.log")
    srv_pid = os.path.join(results_dir, "iperf3_server.pid")
    json_out = os.path.join(results_dir, f"iperf3_client_{run_tag}.json")

    # Servidor
    start_bg(hdst, "iperf3 -s", srv_pid, srv_log)
    time.sleep(0.5)

    # Cliente
    args = ["-c", "10.0.1.2", "-t", str(duration), "-J"]
    if parallel and parallel > 1:
        args += ["-P", str(parallel)]
    if reverse:
        args += ["--reverse"]
    if udp:
        args += ["-u"]
        if bitrate:
            args += ["-b", str(bitrate)]

    cmd = "iperf3 " + " ".join(shlex.quote(a) for a in args)
    run_cmd(hsrc, cmd, json_out)

    stop_bg(hdst, srv_pid)

    # Normalizar JSON -> CSV común (en el host controlador, más fiable que heredocs)
    rows = normalize_iperf_json_to_rows(
        json_out,
        run_tag=run_tag,
        duration=duration,
        parallel=parallel or 1,
        reverse=reverse,
        udp=udp,
        bitrate=bitrate,
        src="hsrc",
        dst="hdst",
    )
    norm.append_rows(rows)

    print(f"[OK] iPerf3 JSON en {json_out} | Normalizado -> {norm.out_csv}")


def _try_extract_json_metrics(text: str) -> Optional[Dict[str, Any]]:
    """
    Para 'custom': si tu script imprime un JSON en alguna línea (idealmente la última), lo detectamos.
    """
    # busca la última línea que parezca JSON
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in reversed(lines[-50:]):  # limita trabajo
        if ln.startswith("{") and ln.endswith("}"):
            try:
                return json.loads(ln)
            except Exception:
                continue
    return None


def custom_test(net, repo_root, script_path, args, results_dir, run_tag: str):
    """
    Ejecuta tu script (en hsrc) y guarda stdout/stderr.
    Para integrar con el CSV normalizado, tienes 3 opciones:

      A) (Recomendado) Tu script imprime al final una línea JSON con métricas, por ejemplo:
         {"throughput_bps": 1234, "rx_bytes": 999, "tx_bytes": 111, "rx_pps": 10, "tx_pps": 11, "loss_percent": 0.1}

      B) Tu script genera uno o varios CSVs en results_dir: intentaremos normalizarlos (mapeo flexible).

      C) Si no hay métricas parseables, igual dejamos constancia en el CSV normalizado (fila "NO_METRICS").
    """
    out_csv = per_test_csv(results_dir, "custom", run_tag)
    norm = NormalizedCSVWriter(out_csv)
    hsrc = net["hsrc"]
    ensure_dir(hsrc, results_dir)

    script_abs = abspath(repo_root, script_path)
    log_path = os.path.join(results_dir, f"custom_{run_tag}.log")
    cmd = " ".join([shlex.quote(script_abs)] + [shlex.quote(a) for a in args])

    # Asegura ejecutable
    hsrc.cmd(f"chmod +x {shlex.quote(script_abs)} >/dev/null 2>&1 || true")
    out = run_cmd(hsrc, cmd, log_path)

    # 1) Intentar extraer JSON de salida directa (si no rediriges). En nuestro caso redirigimos, así que leemos log.
    try:
        with open(log_path, "r") as f:
            log_txt = f.read()
    except Exception:
        log_txt = ""

    metrics = _try_extract_json_metrics(log_txt)
    if metrics:
        row = {k: "" for k in NORMALIZED_COLUMNS}
        row.update(
            {
                "run_tag": run_tag,
                "mode": "custom",
                "tool": os.path.basename(script_abs),
                "timestamp_utc": _utc_now_iso(),
                "src": "hsrc",
                "dst": "hdst",
                "notes": "JSON_METRICS",
            }
        )
        # deja que entren solo keys conocidas por NORMALIZED_COLUMNS (extras se ignoran)
        row.update(metrics)
        norm.append_rows([row])
        print(f"[OK] Custom: métricas JSON detectadas -> {norm.out_csv}")
        return

    # 2) Intentar normalizar CSVs generados
    rows = normalize_generic_csvs(results_dir, run_tag=run_tag, mode="custom", tool=os.path.basename(script_abs))
    if rows:
        norm.append_rows(rows)
        print(f"[OK] Custom: CSVs detectados y normalizados -> {norm.out_csv}")
        return

    # 3) No hay métricas
    norm.append_rows(
        [
            {
                "run_tag": run_tag,
                "mode": "custom",
                "tool": os.path.basename(script_abs),
                "timestamp_utc": _utc_now_iso(),
                "src": "hsrc",
                "dst": "hdst",
                "notes": f"NO_METRICS (see {os.path.basename(log_path)})",
            }
        ]
    )
    print(f"[OK] Custom: log en {log_path} | Sin métricas parseables -> {norm.out_csv}")


# -----------------------------
# Main
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="Runner de experimentos Mininet (CSV normalizado): tcpreplay, iperf, custom")
    ap.add_argument("--repo-root", required=True, help="Ruta absoluta al root del repo")
    ap.add_argument("--results-dir", default=None, help="Directorio resultados (por defecto /tmp/exp_<mode>_<timestamp>)")
    ap.add_argument("--keep-alive", action="store_true", help="Mantener la red viva al final (Ctrl+C para salir)")

    sub = ap.add_subparsers(dest="mode", required=True)

    # tcpreplay
    ap_t = sub.add_parser("tcpreplay", help="Ejecuta rx_capture_server + runner tcpreplay sweep")
    ap_t.add_argument("--pcap", required=True, help="Ruta al PCAP (abs o relativa al repo)")
    ap_t.add_argument("--duration", type=int, default=10)
    ap_t.add_argument("--ctrl-port", type=int, default=5555)
    ap_t.add_argument("--prefix", default="tcpreplay")
    ap_t.add_argument("--reps", type=int, default=1)

    # iperf
    ap_i = sub.add_parser("iperf", help="Ejecuta iperf3 server/client y vuelca a CSV normalizado")
    ap_i.add_argument("--duration", type=int, default=10)
    ap_i.add_argument("--parallel", type=int, default=1)
    ap_i.add_argument("--reverse", action="store_true")
    ap_i.add_argument("--udp", action="store_true")
    ap_i.add_argument("--bitrate", default=None, help="Solo UDP, ej: 100M, 1G")

    # custom
    ap_c = sub.add_parser("custom", help="Ejecuta tu script propio (en hsrc) y guarda log")
    ap_c.add_argument("--script", required=True, help="Ruta script (abs o relativa al repo)")
    ap_c.add_argument("args", nargs=argparse.REMAINDER, help="Argumentos extra para tu script (pon -- antes)")

    args = ap.parse_args()
    repo_root = args.repo_root

    results_dir = args.results_dir
    if not results_dir:
        results_dir = f"/tmp/exp_{args.mode}_{now_tag()}"
    ensure_dir_local(results_dir)

    # CSV normalizado único por carpeta de resultados

    # Un tag por ejecución (para agrupar filas)
    run_tag = now_tag()

    # Construir red
    net = Mininet(
        topo=SimpleTopo(),
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False,
    )

    net.start()
    try:
        ping_sanity(net)

        if args.mode == "tcpreplay":
            tcpreplay_test(
                net,
                repo_root=repo_root,
                pcap=args.pcap,
                duration=args.duration,
                ctrl_port=args.ctrl_port,
                prefix=args.prefix,
                reps=args.reps,
                results_dir=results_dir,
                norm=norm,
                run_tag=run_tag,
            )

        elif args.mode == "iperf":
            iperf_test(
                net,
                results_dir=results_dir,
                duration=args.duration,
                parallel=args.parallel,
                reverse=args.reverse,
                udp=args.udp,
                bitrate=args.bitrate,
                norm=norm,
                run_tag=run_tag,
            )

        elif args.mode == "custom":
            extra = args.args
            if extra and extra[0] == "--":
                extra = extra[1:]
            custom_test(
                net,
                repo_root=repo_root,
                script_path=args.script,
                args=extra,
                results_dir=results_dir,
                norm=norm,
                run_tag=run_tag,
            )

        if args.keep_alive:
            print("[INFO] keep-alive activo. Ctrl+C para terminar.")
            while True:
                time.sleep(1)

    finally:
        net.stop()
        print(f"[INFO] Resultados: {results_dir}")
        print(f"[INFO] CSV normalizado: {normalized_csv}")


if __name__ == "__main__":
    setLogLevel("info")
    main()
