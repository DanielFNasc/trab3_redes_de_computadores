#!/usr/bin/env python3
"""
Relatório do Trabalho 3: junta o que os clientes enviaram, o que o servidor
(H3) recebeu e o que o switch contou, e compara as execuções.

    python3 anomalia_report.py                 (no diretório dos scripts)
    python3 anomalia_report.py --no-plots      (só tabelas e CSV)

Para cada execução calcula, em três janelas (antes / durante / depois da
anomalia de H2):
    - vazão recebida em H3 (Mbps) por host
    - perda de pacotes UDP por host (por número de sequência)
    - RTT de H1 (média, p95, máximo) e perda de sondas
    - tempo de detecção de H2 (switch: 1º alarme - 1º pacote de H2)
    - % de pacotes de H2 descartados pelo switch

Saídas em anom_obs/: resumo.csv, serie_run<N>.csv e, se houver matplotlib,
vazao_por_execucao.png, rtt_h1.png e comparacao.png.
Apenas biblioteca padrão (matplotlib é opcional).
"""

import argparse
import csv
import glob
import json
import math
import os
import re
import sys

HOSTS = ("h1", "h2")
DEFAULT_OBS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "anom_obs"
)


# ----------------------------------------------------------------------
# Carga dos dados
# ----------------------------------------------------------------------

def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def load_runs(obs_dir):
    runs = {}
    for path in glob.glob(os.path.join(obs_dir, "sent_run*_*.json")):
        m = re.search(r"sent_run(\d+)_(h[12])\.json$", path)
        if not m:
            continue
        n, host = int(m.group(1)), m.group(2)
        data = load_json(path)
        if data is None:
            continue
        r = runs.setdefault(n, {"id": n, "sent": {}})
        r["sent"][host] = data
    for n, r in runs.items():
        r["server"] = load_json(os.path.join(obs_dir, "server_run%d.json" % n))
        r["switch"] = load_json(os.path.join(obs_dir, "switch_run%d.json" % n))
        first = next(iter(r["sent"].values()))
        r["label"] = first["label"]
    return runs


# ----------------------------------------------------------------------
# Cálculos
# ----------------------------------------------------------------------

def percentile(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    return s[int(round(p / 100.0 * (len(s) - 1)))]


def mean(vals):
    return sum(vals) / len(vals) if vals else None


def sec_window(a_abs, b_abs):
    """Segundos inteiros que cabem inteiros em [a_abs, b_abs)."""
    lo = int(math.floor(a_abs)) + 1
    hi = int(math.floor(b_abs))
    return list(range(lo, hi)) if hi > lo else []


def recv_rec(run, host):
    sent = run["sent"].get(host)
    if sent is None or run["server"] is None:
        return None
    return run["server"].get(sent["proto"], {}).get(host)


def recv_mbps(run, host, secs):
    rec = recv_rec(run, host)
    if rec is None or not secs:
        return None
    total = sum(rec["bytes_by_sec"].get(str(s), 0) for s in secs)
    return total * 8.0 / len(secs) / 1e6


def sent_mbps(run, host, secs):
    sent = run["sent"].get(host)
    if sent is None or not secs:
        return None
    total = sum(sent["sent_by_sec"].get(str(s), [0, 0])[1] for s in secs)
    return total * 8.0 / len(secs) / 1e6


def first_seq_at(sent, sec):
    keys = sorted(int(k) for k in sent["first_seq_by_sec"])
    for k in keys:
        if k >= sec:
            return sent["first_seq_by_sec"][str(k)]
    return sent["seq_end"]


def received_in(ranges, lo, hi):
    total = 0
    for a, b in ranges:
        x, y = max(a, lo), min(b + 1, hi)
        if y > x:
            total += y - x
    return total


def udp_loss_pct(run, host, secs):
    sent = run["sent"].get(host)
    rec = recv_rec(run, host)
    if sent is None or sent["proto"] != "udp" or not secs:
        return None
    if rec is None:
        rec = {"seq_ranges": []}
    lo = first_seq_at(sent, secs[0])
    hi = first_seq_at(sent, secs[-1] + 1)
    if hi <= lo:
        return None
    got = received_in(rec["seq_ranges"], lo, hi)
    return 100.0 * (hi - lo - got) / (hi - lo)


def rtt_stats(run, a_abs, b_abs):
    sent = run["sent"].get("h1")
    if sent is None or not sent.get("probe"):
        return None
    lo, hi = a_abs - sent["t0"], b_abs - sent["t0"]
    samples = [s for s in sent["probe"]["samples"] if lo <= s[0] < hi]
    if not samples:
        return None
    ok = [s[1] for s in samples if s[1] is not None]
    return {
        "mean": mean(ok), "p95": percentile(ok, 95),
        "max": max(ok) if ok else None,
        "loss": 100.0 * (len(samples) - len(ok)) / len(samples),
    }


def analyze(run):
    sent = run["sent"]
    t_ref = min(s["t0"] for s in sent.values())
    end_abs = max(s["t0"] + s["duration"] for s in sent.values())

    h2 = sent.get("h2")
    if h2 and h2["phases"]:
        ph = max(h2["phases"], key=lambda p: p[2] if p[2] > 0 else 1e9)
        ws = h2["t0"] + ph[0]
        we = ws + ph[1]
        run["window_rate"] = ph[2]
    else:
        ws, we = t_ref, end_abs
        run["window_rate"] = None

    run.update({"t_ref": t_ref, "end_abs": end_abs, "ws": ws, "we": we})
    wins = {
        "antes": sec_window(t_ref, ws),
        "anomalia": sec_window(ws, we),
        "depois": list(range(int(math.floor(we)) + 2, int(math.floor(end_abs)))),
    }
    run["wins"] = wins

    res = {}
    for name, secs in wins.items():
        res[name] = {}
        for h in HOSTS:
            offered = sent_mbps(run, h, secs)
            if not offered or offered <= 0.01:      # host não enviou nada nesta janela
                res[name][h] = {"sent": None, "recv": None, "loss": None}
                continue
            res[name][h] = {
                "sent": offered,
                "recv": recv_mbps(run, h, secs),
                "loss": udp_loss_pct(run, h, secs),
            }
    res["anomalia"]["rtt"] = rtt_stats(run, ws, we)
    res["antes"]["rtt"] = rtt_stats(run, t_ref, ws)
    res["depois"]["rtt"] = rtt_stats(run, we + 2, end_abs)
    run["res"] = res

    sw = (run["switch"] or {}).get("hosts", {}).get("2")
    run["sw2"] = sw
    run["tcp2"] = (h2 or {}).get("tcp") if h2 else None


# ----------------------------------------------------------------------
# Apresentação
# ----------------------------------------------------------------------

def f(x, nd=2):
    return "-" if x is None else ("%.*f" % (nd, x))


def print_run(run):
    res = run["res"]
    mode = (run["switch"] or {}).get("mode_name", "?")
    print("=" * 74)
    print("Execução %d: %s   (modo do switch: %s)" % (run["id"], run["label"], mode))
    rate = run["window_rate"]
    print("Janela anômala: %.1f s a %.1f s (relativo ao início), taxa de H2 = %s" % (
        run["ws"] - run["t_ref"], run["we"] - run["t_ref"],
        "máxima possível (TCP)" if rate == 0 else "%s Mbps" % f(rate, 1)))
    if run["server"] is None:
        print("[AVISO] server_run%d.json ausente: servidor não gravou dados." % run["id"])
    print("-" * 74)
    print("%-26s %12s %12s %12s" % ("", "antes", "anomalia", "depois"))
    for h in HOSTS:
        for key, name, nd in (("sent", "oferecido", 2), ("recv", "recebido em H3", 2), ("loss", "perda UDP (%)", 1)):
            vals = [res[w][h][key] for w in ("antes", "anomalia", "depois")]
            if all(v is None for v in vals):
                continue
            print("%-26s %12s %12s %12s" % (
                "%s %s%s" % (h.upper(), name, " (Mbps)" if key != "loss" else ""),
                f(vals[0], nd), f(vals[1], nd), f(vals[2], nd)))
    for key, name in (("mean", "RTT médio H1 (ms)"), ("p95", "RTT p95 H1 (ms)"),
                      ("max", "RTT máx H1 (ms)"), ("loss", "sondas perdidas H1 (%)")):
        vals = [(res[w].get("rtt") or {}).get(key) for w in ("antes", "anomalia", "depois")]
        if any(v is not None for v in vals):
            print("%-26s %12s %12s %12s" % (name, f(vals[0], 1), f(vals[1], 1), f(vals[2], 1)))
    print("-" * 74)
    sw = run["sw2"]
    if sw:
        estado = "ELEFANTE" if sw["det_state"] else "normal"
        print("Switch, H2: tempo de detecção = %s ms | alarmes = %d | estado final = %s"
              % (f(sw["detect_ms"], 1), sw["det_alarms"], estado))
        print("            pacotes encaminhados = %d | descartados = %d (%.1f%%)"
              % (sw["stat_pass_pkts"], sw["stat_drop_pkts"], sw["drop_pct"]))
    else:
        print("Switch: switch_run%d.json ausente (rode 'sh python3 anomalia_ctl.py stats --run %d')."
              % (run["id"], run["id"]))
    tcp = run["tcp2"]
    if tcp and "retrans" in tcp and tcp.get("outsegs"):
        print("TCP de H2: %d retransmissões em %d segmentos (%.1f%%)%s" % (
            tcp["retrans"], tcp["outsegs"], 100.0 * tcp["retrans"] / tcp["outsegs"],
            "  erro: " + tcp["error"] if tcp.get("error") else ""))


def summary_rows(runs):
    rows = []
    for n in sorted(runs):
        r = runs[n]
        a = r["res"]["anomalia"]
        rtt = a.get("rtt") or {}
        sw = r["sw2"] or {}
        tcp = r["tcp2"] or {}
        retr = None
        if tcp.get("outsegs"):
            retr = 100.0 * tcp.get("retrans", 0) / tcp["outsegs"]
        rows.append({
            "run": n,
            "rotulo": r["label"],
            "modo": (r["switch"] or {}).get("mode_name", "?"),
            "h1_mbps": a["h1"]["recv"],
            "h1_perda_pct": a["h1"]["loss"],
            "h1_rtt_medio_ms": rtt.get("mean"),
            "h1_rtt_p95_ms": rtt.get("p95"),
            "h1_rtt_max_ms": rtt.get("max"),
            "h2_mbps": a["h2"]["recv"],
            "h2_perda_pct": a["h2"]["loss"],
            "h2_retrans_pct": retr,
            "deteccao_ms": sw.get("detect_ms"),
            "h2_descarte_switch_pct": sw.get("drop_pct"),
            "h2_estado_final": None if not sw else ("elefante" if sw["det_state"] else "normal"),
            "janela_ini_s": round(r["ws"] - r["t_ref"], 2),
            "janela_fim_s": round(r["we"] - r["t_ref"], 2),
        })
    return rows


def print_summary(rows):
    print("=" * 74)
    print("RESUMO NA JANELA ANÔMALA (H2 em taxa alta)")
    print("-" * 74)
    cols = [("run", 3, "%d"), ("rotulo", 22, "%s"), ("modo", 5, "%s"),
            ("h1_mbps", 6, 2), ("h1_perda_pct", 6, 1), ("h1_rtt_medio_ms", 8, 1),
            ("h1_rtt_p95_ms", 8, 1), ("h2_mbps", 6, 2), ("h2_perda_pct", 6, 1),
            ("deteccao_ms", 7, 1), ("h2_descarte_switch_pct", 7, 1)]
    heads = ["run", "rótulo", "modo", "H1Mbps", "H1perd%", "H1RTTm", "H1RTT95",
             "H2Mbps", "H2perd%", "detec.ms", "H2desc%"]
    print(" ".join("%*s" % (w, h) for (_, w, _), h in zip(cols, heads)))
    for row in rows:
        out = []
        for key, w, fmt in cols:
            v = row[key]
            if isinstance(fmt, int):
                out.append("%*s" % (w, f(v, fmt)))
            else:
                out.append("%*s" % (w, fmt % v))
        print(" ".join(out))
    print("(H1RTTm/H1RTT95 = RTT médio/p95 de H1 em ms; perda UDP calculada por nº de sequência;")
    print(" detec.ms = 1º alarme - 1º pacote de H2, medido no switch; H2desc% = descartes do detector)")


def write_csvs(runs, rows, out_dir):
    path = os.path.join(out_dir, "resumo.csv")
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for row in rows:
            w.writerow({k: ("" if v is None else v) for k, v in row.items()})
    print("CSV: %s" % path)
    for n, r in sorted(runs.items()):
        path = os.path.join(out_dir, "serie_run%d.csv" % n)
        base = int(math.floor(r["t_ref"]))
        with open(path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["t_s", "h1_oferecido_mbps", "h1_recebido_mbps",
                        "h2_oferecido_mbps", "h2_recebido_mbps"])
            for s in range(base, int(math.floor(r["end_abs"])) + 3):
                w.writerow([s - base] + [
                    round(v or 0.0, 3) for v in (
                        sent_mbps(r, "h1", [s]), recv_mbps(r, "h1", [s]),
                        sent_mbps(r, "h2", [s]), recv_mbps(r, "h2", [s]))])
        sent1 = r["sent"].get("h1")
        if sent1 and sent1.get("probe"):
            path = os.path.join(out_dir, "rtt_run%d.csv" % n)
            shift = sent1["t0"] - r["t_ref"]
            with open(path, "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["t_s", "rtt_ms"])      # rtt vazio = sonda perdida
                for t, rtt in sent1["probe"]["samples"]:
                    w.writerow([round(t + shift, 3), "" if rtt is None else rtt])


# ----------------------------------------------------------------------
# Gráficos (opcionais)
# ----------------------------------------------------------------------

def make_plots(runs, rows, out_dir, gargalo=10.0):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[AVISO] matplotlib não instalado: gráficos não gerados "
              "(os CSV em %s servem para plotar em outra máquina)." % out_dir)
        return

    c1, c2 = "#1f77b4", "#e07b00"
    ids = sorted(runs)

    # 1) vazão por segundo, uma figura com um gráfico por execução
    ncols = 2
    nrows = (len(ids) + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(12, 2.8 * nrows), sharey=True, squeeze=False)
    for ax in axes.flat:
        ax.set_visible(False)
    gmax = 1.2 * gargalo
    for ax, n in zip(axes.flat, ids):
        ax.set_visible(True)
        r = runs[n]
        base = int(math.floor(r["t_ref"]))
        xs = list(range(0, int(math.floor(r["end_abs"])) - base + 3))
        h1 = [recv_mbps(r, "h1", [base + x]) or 0.0 for x in xs]
        h2 = [recv_mbps(r, "h2", [base + x]) or 0.0 for x in xs]
        gmax = max(gmax, 1.05 * max(h1 + h2))
        ax.axvspan(r["ws"] - base, r["we"] - base, color="#d62728", alpha=0.08)
        # cada valor vale para o segundo [x, x+1): curva em degraus
        ax.step(xs, h1, where="post", color=c1, label="H1 (normal)")
        ax.step(xs, h2, where="post", color=c2, label="H2 (elefante)")
        ax.axhline(gargalo, color="gray", lw=0.8, ls=":")
        mode = (r["switch"] or {}).get("mode_name", "?")
        ax.set_title("run %d: %s (%s)" % (n, r["label"], mode), fontsize=9)
        ax.set_ylabel("Mbps em H3")
        ax.grid(alpha=0.3)
    axes.flat[0].set_ylim(0, gmax)
    for ax in axes[-1]:
        ax.set_xlabel("tempo (s)")
    axes.flat[0].legend(loc="upper right", fontsize=8)
    fig.suptitle("Vazão recebida em H3 (sombreado = anomalia; ponteado = gargalo de %g Mbps)" % gargalo,
                 fontsize=10)
    fig.tight_layout()
    p = os.path.join(out_dir, "vazao_por_execucao.png")
    fig.savefig(p, dpi=130)
    plt.close(fig)
    print("Gráfico: %s" % p)

    # 2) RTT de H1
    fig, ax = plt.subplots(figsize=(10, 4.5))
    any_rtt = False
    for n in ids:
        r = runs[n]
        sent = r["sent"].get("h1")
        if not sent or not sent.get("probe"):
            continue
        pts = [(s[0], s[1]) for s in sent["probe"]["samples"] if s[1] is not None]
        if not pts:
            continue
        any_rtt = True
        ax.plot([p[0] for p in pts], [p[1] for p in pts], lw=1,
                label="run %d: %s" % (n, r["label"]))
    if any_rtt:
        ax.set_yscale("log")
        ax.set_xlabel("tempo (s)")
        ax.set_ylabel("RTT de H1 (ms, escala log)")
        ax.set_title("RTT de H1 durante os experimentos")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=7, ncol=2)
        fig.tight_layout()
        p = os.path.join(out_dir, "rtt_h1.png")
        fig.savefig(p, dpi=130)
        print("Gráfico: %s" % p)
    plt.close(fig)

    # 3) comparação das execuções na janela anômala
    fig, axes = plt.subplots(1, 3, figsize=(13, 4))
    labels = ["%d\n%s" % (r["run"], r["rotulo"]) for r in rows]
    xs = list(range(len(rows)))
    w = 0.38
    axes[0].bar([x - w / 2 for x in xs], [r["h1_mbps"] or 0 for r in rows], w, color=c1, label="H1")
    axes[0].bar([x + w / 2 for x in xs], [r["h2_mbps"] or 0 for r in rows], w, color=c2, label="H2")
    axes[0].set_title("Vazão na janela anômala (Mbps)")
    axes[0].legend(fontsize=8)
    axes[1].bar(xs, [r["h1_rtt_medio_ms"] or 0 for r in rows], 0.6, color=c1)
    axes[1].set_title("RTT médio de H1 (ms)")
    axes[2].bar(xs, [r["h1_perda_pct"] or 0 for r in rows], 0.6, color=c1)
    axes[2].set_title("Perda UDP de H1 (%)")
    for ax in axes:
        ax.set_xticks(xs)
        ax.set_xticklabels(labels, fontsize=6)
        ax.grid(alpha=0.3, axis="y")
    fig.tight_layout()
    p = os.path.join(out_dir, "comparacao.png")
    fig.savefig(p, dpi=130)
    plt.close(fig)
    print("Gráfico: %s" % p)


# ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Relatório do Trabalho 3.")
    ap.add_argument("--obs-dir", default=DEFAULT_OBS_DIR)
    ap.add_argument("--no-plots", action="store_true", help="não gerar gráficos")
    ap.add_argument("--gargalo", type=float, default=10.0,
                    help="capacidade do enlace S1-H3 em Mbps, para os gráficos (padrão: %(default)g)")
    args = ap.parse_args()

    obs_dir = os.path.abspath(args.obs_dir)
    if not os.path.isdir(obs_dir):
        sys.exit("[ERRO] diretório %s não encontrado." % obs_dir)
    runs = load_runs(obs_dir)
    if not runs:
        sys.exit("[ERRO] nenhum sent_run*_*.json em %s: rode os clientes primeiro." % obs_dir)

    for n in sorted(runs):
        analyze(runs[n])
        print_run(runs[n])
    rows = summary_rows(runs)
    print_summary(rows)
    write_csvs(runs, rows, obs_dir)
    if not args.no_plots:
        make_plots(runs, rows, obs_dir, args.gargalo)


if __name__ == "__main__":
    main()

