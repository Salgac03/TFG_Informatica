#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plot_exp_suite_6fig.py

SOLO 6 graficas (2 por fase) con comparacion XDP OFF vs ON:

FASE IPERF (2 lineas por grafica):
  1) iperf: bps_measured vs pps_target (XDP off/on)
  2) iperf: lost_percent vs pps_target (XDP off/on)

FASE TCPREPLAY (2 graficas, 4 lineas: legit/malign x off/on):
  3) tcpreplay: pps_measured vs pps_target
     lineas: legit off, legit on, malign off, malign on
  4) tcpreplay: lost_percent vs pps_target
     lineas: legit off, legit on, malign off, malign on

FASE GENERADOR (trafico_eth) (2 lineas por grafica):
  5) trafico_eth: pps_measured vs pps_target (XDP off/on)
  6) trafico_eth: lost_percent vs pps_target (XDP off/on)

Uso:
  python3 plot_exp_suite_6fig.py --suite-dir /ruta/a/exp_suite_YYYYMMDD_HHMMSS

O CSVs sueltos:
  python3 plot_exp_suite_6fig.py --iperf iperf_results.csv \
      --tcplegit tcpreplay_legit_results.csv --tcpmalign tcpreplay_malign_results.csv \
      --gen trafico_eth_results.csv

Salida (default):
  <suite-dir>/plots_6/01_iperf_bps.png
  ...
  <suite-dir>/plots_6/06_gen_loss.png
"""

import argparse
import os
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


def _read_csv(path: str) -> pd.DataFrame:
    return pd.read_csv(path)


def _maybe_suite_paths(suite_dir: str):
    suite = Path(suite_dir)
    iperf = suite / "iperf" / "iperf_results.csv"
    tcplegit = suite / "tcpreplay" / "legit" / "tcpreplay_legit_results.csv"
    tcpmalign = suite / "tcpreplay" / "malign" / "tcpreplay_malign_results.csv"
    gen1 = suite / "generator" / "trafico_eth" / "trafico_eth_results.csv"
    gen2 = suite / "generator" / "trafico_eth_results.csv"
    return {
        "iperf": str(iperf) if iperf.exists() else None,
        "tcplegit": str(tcplegit) if tcplegit.exists() else None,
        "tcpmalign": str(tcpmalign) if tcpmalign.exists() else None,
        "gen": str(gen1) if gen1.exists() else (str(gen2) if gen2.exists() else None),
    }


def _filter_common(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "xdp" in df.columns:
        df["xdp"] = df["xdp"].astype(str).str.strip().str.lower()
    return df.dropna(how="all")


def _filter_gen(df: pd.DataFrame) -> pd.DataFrame:
    df = _filter_common(df)
    # elimina filas inválidas si existe columna TX total
    for col in ("tx_packets_total", "tx_total", "tx_packets"):
        if col in df.columns:
            df = df[df[col].fillna(0).astype(float) > 0]
            break
    return df


def _ensure_out(out_dir: str) -> str:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    return out_dir


def _save(fig, out_base: str, fmt: str):
    out = f"{out_base}.{fmt}"
    fig.savefig(out, bbox_inches="tight", dpi=200 if fmt == "png" else None)
    print(f"[OK] {out}")
    plt.close(fig)


def plot_iperf(df: pd.DataFrame, out_dir: str, fmt: str):
    df = _filter_common(df)
    x = "pps_target"
    for y, name, title, ylabel in [
        ("bps_measured", "01_iperf_bps", "IPERF: Throughput vs PPS (XDP off/on)", "bits/s"),
        ("lost_percent", "02_iperf_loss", "IPERF: Loss % vs PPS (XDP off/on)", "loss %"),
    ]:
        fig = plt.figure()
        for xdp in ("off", "on"):
            sub = df[df.get("xdp", "") == xdp]
            if sub.empty:
                continue
            plt.plot(sub[x], sub[y], marker="o", label=f"xdp {xdp}")
        plt.title(title)
        plt.xlabel("pps_target")
        plt.ylabel(ylabel)
        plt.legend()
        _save(fig, str(Path(out_dir) / name), fmt)


def plot_tcpreplay(df_legit: pd.DataFrame, df_malign: pd.DataFrame, out_dir: str, fmt: str):
    dl = _filter_common(df_legit)
    dm = _filter_common(df_malign)
    x = "pps_target"
    for y, name, title, ylabel in [
        ("pps_measured", "03_tcpreplay_pps", "TCPReplay: PPS measured vs PPS target", "pps_measured"),
        ("lost_percent", "04_tcpreplay_loss", "TCPReplay: Loss % vs PPS target", "loss %"),
    ]:
        fig = plt.figure()
        for label, df in [("legit", dl), ("malign", dm)]:
            for xdp in ("off", "on"):
                sub = df[df.get("xdp", "") == xdp]
                if sub.empty:
                    continue
                plt.plot(sub[x], sub[y], marker="o", label=f"{label} xdp {xdp}")
        plt.title(title + " (legit/malign; xdp off/on)")
        plt.xlabel("pps_target")
        plt.ylabel(ylabel)
        plt.legend()
        _save(fig, str(Path(out_dir) / name), fmt)


def plot_generator(df: pd.DataFrame, out_dir: str, fmt: str):
    df = _filter_gen(df)
    x = "pps_target"
    y_pps = "pps_measured" if "pps_measured" in df.columns else ("pps" if "pps" in df.columns else None)
    y_loss = "lost_percent" if "lost_percent" in df.columns else ("loss_percent" if "loss_percent" in df.columns else None)
    if not y_pps or not y_loss:
        raise SystemExit(f"No encuentro columnas esperadas en generador. Tengo: {list(df.columns)}")
    for y, name, title, ylabel in [
        (y_pps, "05_gen_pps", "trafico_eth: PPS measured vs PPS target (XDP off/on)", "pps_measured"),
        (y_loss, "06_gen_loss", "trafico_eth: Loss % vs PPS target (XDP off/on)", "loss %"),
    ]:
        fig = plt.figure()
        for xdp in ("off", "on"):
            sub = df[df.get("xdp", "") == xdp]
            if sub.empty:
                continue
            plt.plot(sub[x], sub[y], marker="o", label=f"xdp {xdp}")
        plt.title(title)
        plt.xlabel("pps_target")
        plt.ylabel(ylabel)
        plt.legend()
        _save(fig, str(Path(out_dir) / name), fmt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite-dir", default=None, help="Directorio exp_suite_...")
    ap.add_argument("--iperf", default=None)
    ap.add_argument("--tcplegit", default=None)
    ap.add_argument("--tcpmalign", default=None)
    ap.add_argument("--gen", default=None)
    ap.add_argument("--out-dir", default=None, help="Salida (default: <suite-dir>/plots_6)")
    ap.add_argument("--fmt", choices=["png", "pdf"], default="png")
    args = ap.parse_args()

    iperf = args.iperf
    tcplegit = args.tcplegit
    tcpmalign = args.tcpmalign
    gen = args.gen

    if args.suite_dir:
        found = _maybe_suite_paths(args.suite_dir)
        iperf = iperf or found["iperf"]
        tcplegit = tcplegit or found["tcplegit"]
        tcpmalign = tcpmalign or found["tcpmalign"]
        gen = gen or found["gen"]
        out_dir = args.out_dir or str(Path(args.suite_dir) / "plots_6")
    else:
        out_dir = args.out_dir or str(Path.cwd() / "plots_6")

    if not (iperf and tcplegit and tcpmalign and gen):
        raise SystemExit(
            "Faltan CSVs. Necesito: --iperf, --tcplegit, --tcpmalign, --gen (o usa --suite-dir).\n"
            f"iperf={iperf}\nlegit={tcplegit}\nmalign={tcpmalign}\ngen={gen}"
        )

    for p in (iperf, tcplegit, tcpmalign, gen):
        if not os.path.isfile(p):
            raise SystemExit(f"No existe: {p}")

    _ensure_out(out_dir)

    df_iperf = _read_csv(iperf)
    df_legit = _read_csv(tcplegit)
    df_malign = _read_csv(tcpmalign)
    df_gen = _read_csv(gen)

    plot_iperf(df_iperf, out_dir, args.fmt)
    plot_tcpreplay(df_legit, df_malign, out_dir, args.fmt)
    plot_generator(df_gen, out_dir, args.fmt)

    print(f"[DONE] Graficas en: {out_dir}")


if __name__ == "__main__":
    main()
