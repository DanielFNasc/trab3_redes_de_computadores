#!/usr/bin/env python3
"""
Gerador de tráfego e medidor de RTT do Trabalho 3 (fluxo elefante em P4).
Executar em H1 e H2 (o servidor anomalia_server.py roda em H3).

O tráfego é descrito por FASES, cada uma no formato INICIO:DURACAO:TAXA
(segundos relativos ao começo do cliente; TAXA em Mbps de payload):

    --phase 0:20:2          2 Mbps durante os 20 s
    --phase 5:10:15         de 5 s a 15 s a 15 Mbps (elefante)
    --phase 15:5:2          de 15 s a 20 s volta a 2 Mbps (recuperação)
    --phase 5:10:0          taxa 0 = "o mais rápido possível" (só TCP)

--proto udp  : taxa constante (CBR) de datagramas de 1200 bytes
--proto tcp  : um fluxo TCP único que bombeia dados (taxa 0 = sem limite)
--probe      : além dos dados, envia sondas UDP de 10 por segundo para o
               servidor de eco e mede o RTT (ping não serve: o NAT descarta ICMP)

Exemplos (CLI do Mininet; o CLI troca "h1"/"h2" pelo IP, o script aceita os dois):

    h1 python3 anomalia_client.py h1 --run 2 --label udp-total --proto udp \\
        --phase 0:20:2 --probe --duration 20 > /tmp/anom_r2_h1.txt 2>&1 &
    h2 python3 anomalia_client.py h2 --run 2 --label udp-total --proto udp \\
        --phase 5:10:15 --phase 15:5:2 > /tmp/anom_r2_h2.txt 2>&1

Resultado: anom_obs/sent_run<N>_<host>.json. Apenas biblioteca padrão.
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time

SERVER_IP = "200.0.0.2"
UDP_DATA_PORT = 9101
TCP_DATA_PORT = 9102
ECHO_PORT = 9103

HOST_IP = {"h1": "10.0.0.1", "h2": "10.0.0.2"}
HOST_ID = {"h1": 1, "h2": 2}

HDR = struct.Struct("!HBIQ")      # run, id do host, seq, t_envio_ns
HELLO = struct.Struct("!HB")      # run, id do host (início da conexão TCP)

PAYLOAD = 1200                    # bytes de payload UDP dos dados
PROBE_PAYLOAD = 64                # bytes das sondas de RTT
PROBE_INTERVAL = 0.1              # 10 sondas por segundo
PROBE_GRACE = 2.5                 # espera pelas últimas respostas
MAX_LAG = 0.02                    # atraso máximo tolerado antes de "perder" o ritmo (s)

DEFAULT_OBS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "anom_obs"
)


# ----------------------------------------------------------------------
# Utilitários
# ----------------------------------------------------------------------

def parse_target(value):
    # O CLI do Mininet troca nomes de hosts pelos IPs na linha de comando.
    aliases = {}
    for host, ip in HOST_IP.items():
        aliases[host] = host
        aliases[ip] = host
    target = aliases.get(value.strip().lower())
    if target is None:
        raise argparse.ArgumentTypeError(
            "'%s' inválido (use h1, h2 ou o IP do host)" % value)
    return target


def parse_phase(text):
    try:
        start, dur, rate = [float(x) for x in text.split(":")]
    except ValueError:
        raise argparse.ArgumentTypeError(
            "fase '%s' inválida (use INICIO:DURACAO:TAXA, ex.: 5:10:15)" % text)
    if start < 0 or dur <= 0 or rate < 0:
        raise argparse.ArgumentTypeError("fase '%s' com valores inválidos" % text)
    return (start, dur, rate)


def sleep_until(t):
    delay = t - time.time()
    if delay > 0:
        time.sleep(delay)


def read_tcp_snmp():
    """Lê RetransSegs e OutSegs do namespace de rede deste host."""
    try:
        with open("/proc/net/snmp") as f:
            lines = [l.split() for l in f if l.startswith("Tcp:")]
        names, values = lines[0][1:], lines[1][1:]
        d = dict(zip(names, values))
        return {"retrans": int(d["RetransSegs"]), "outsegs": int(d["OutSegs"])}
    except (OSError, IndexError, KeyError, ValueError):
        return None


class SendStats:
    def __init__(self):
        self.pkts = 0
        self.bytes = 0
        self.errors = 0
        self.last_seq = -1
        self.by_sec = {}            # segundo absoluto -> [pacotes, bytes]
        self.first_seq_by_sec = {}  # segundo absoluto -> 1ª seq enviada nele

    def record(self, seq, nbytes):
        sec = int(time.time())
        self.last_seq = seq
        self.first_seq_by_sec.setdefault(sec, seq)
        cell = self.by_sec.setdefault(sec, [0, 0])
        cell[0] += 1
        cell[1] += nbytes
        self.pkts += 1
        self.bytes += nbytes


# ----------------------------------------------------------------------
# Emissores de dados
# ----------------------------------------------------------------------

def udp_sender(args, run, hid, t0, phases, st):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((args.server_ip, UDP_DATA_PORT))
    pad = b"\0" * (PAYLOAD - HDR.size)
    seq = 0
    for start, dur, rate in phases:
        if rate <= 0:
            print("[ERRO] fase UDP com taxa 0 não é permitida")
            continue
        t_start, t_end = t0 + start, t0 + start + dur
        interval = (PAYLOAD * 8.0) / (rate * 1e6)
        sleep_until(t_start)
        nxt = time.time()
        while True:
            now = time.time()
            if now >= t_end:
                break
            if now < nxt:
                time.sleep(nxt - now)
                if time.time() >= t_end:
                    break
            pkt = HDR.pack(run, hid, seq & 0xFFFFFFFF, time.monotonic_ns()) + pad
            try:
                sock.send(pkt)
                st.record(seq, len(pkt))
            except OSError:
                st.errors += 1
            seq += 1
            nxt += interval
            if time.time() - nxt > MAX_LAG:   # ficou para trás: não faz rajada de compensação
                nxt = time.time()
    sock.close()


def tcp_sender(args, run, hid, t0, phases, st, out):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Buffer de envio pequeno: o que o cliente "enviou" fica próximo do que foi entregue.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    try:
        sock.settimeout(5)
        sock.connect((args.server_ip, TCP_DATA_PORT))
        sock.sendall(HELLO.pack(run, hid))
    except OSError as exc:
        out["error"] = "connect: %s: %s" % (type(exc).__name__, exc)
        sock.close()
        return
    sock.settimeout(0.5)
    seq = 0
    for start, dur, rate in phases:
        t_start, t_end = t0 + start, t0 + start + dur
        sleep_until(t_start)
        if rate <= 0:
            chunk = b"\0" * 16384
            interval = 0.0
        else:
            chunk = b"\0" * PAYLOAD
            interval = (PAYLOAD * 8.0) / (rate * 1e6)
        nxt = time.time()
        while True:
            now = time.time()
            if now >= t_end:
                break
            if interval and now < nxt:
                time.sleep(nxt - now)
                if time.time() >= t_end:
                    break
            try:
                n = sock.send(chunk)
            except socket.timeout:
                continue                       # conexão travada (descartes): tenta de novo
            except OSError as exc:
                out["error"] = "send: %s: %s" % (type(exc).__name__, exc)
                sock.close()
                return
            st.record(seq, n)
            seq += 1
            if interval:
                nxt += interval
                if time.time() - nxt > MAX_LAG:
                    nxt = time.time()
    sock.close()


# ----------------------------------------------------------------------
# Sondas de RTT
# ----------------------------------------------------------------------

def probe_runner(args, run, hid, t0, duration, out):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((args.server_ip, ECHO_PORT))
    sock.settimeout(0.2)
    samples = {}          # seq -> [t_relativo_de_envio, rtt_ms ou None]
    stop = threading.Event()
    pad = b"\0" * (PROBE_PAYLOAD - HDR.size)

    def rx():
        while not stop.is_set():
            try:
                data = sock.recv(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            now_ns = time.monotonic_ns()
            if len(data) < HDR.size:
                continue
            r, h, seq, t_ns = HDR.unpack_from(data)
            if r != run or h != hid:
                continue
            s = samples.get(seq)
            if s is not None and s[1] is None:
                s[1] = (now_ns - t_ns) / 1e6

    rx_thread = threading.Thread(target=rx, daemon=True)
    rx_thread.start()

    n = int(duration / PROBE_INTERVAL)
    for i in range(n):
        sleep_until(t0 + i * PROBE_INTERVAL)
        samples[i] = [time.time() - t0, None]
        try:
            sock.send(HDR.pack(run, hid, i, time.monotonic_ns()) + pad)
        except OSError:
            pass
    time.sleep(PROBE_GRACE)
    stop.set()
    rx_thread.join(timeout=1)
    sock.close()
    out["interval"] = PROBE_INTERVAL
    out["sent"] = n
    out["samples"] = [[round(samples[i][0], 4),
                       None if samples[i][1] is None else round(samples[i][1], 3)]
                      for i in range(n)]


# ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Gerador de tráfego e RTT do Trabalho 3.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("target", type=parse_target,
                    help="h1 ou h2 (o IP também é aceito: o CLI do Mininet troca nomes por IPs)")
    ap.add_argument("--run", type=int, required=True, help="número da execução (1..65535)")
    ap.add_argument("--label", default="run", help="rótulo da execução (sem espaços)")
    ap.add_argument("--proto", choices=("udp", "tcp"), default="udp")
    ap.add_argument("--phase", type=parse_phase, action="append", default=[],
                    metavar="INICIO:DURACAO:TAXA",
                    help="fase de tráfego (repetível); taxa em Mbps")
    ap.add_argument("--probe", action="store_true",
                    help="mede RTT com sondas UDP de 10 por segundo")
    ap.add_argument("--duration", type=float, default=0.0,
                    help="duração das sondas em s (padrão: fim da última fase)")
    ap.add_argument("--server-ip", default=SERVER_IP,
                    help="IP do servidor (padrão: %(default)s)")
    ap.add_argument("--obs-dir", default=DEFAULT_OBS_DIR)
    args = ap.parse_args()

    if not args.phase and not args.probe:
        ap.error("informe ao menos uma --phase ou --probe")
    if not 1 <= args.run <= 65535:
        ap.error("--run deve estar entre 1 e 65535")

    host = args.target
    hid = HOST_ID[host]
    phases = sorted(args.phase)
    end = max([s + d for s, d, _ in phases], default=0.0)
    duration = args.duration if args.duration > 0 else end
    if args.probe and duration <= 0:
        ap.error("com --probe e sem --phase, informe --duration")

    obs_dir = os.path.abspath(args.obs_dir)
    os.makedirs(obs_dir, exist_ok=True)

    print("=== %s: run %d (%s) proto=%s fases=%s sonda=%s ===" % (
        host.upper(), args.run, args.label, args.proto,
        ["%g:%g:%g" % p for p in phases], args.probe), flush=True)

    t0 = time.time() + 0.3            # pequena folga para as threads subirem
    st = SendStats()
    probe_out = {}
    tcp_out = {}
    snmp_before = read_tcp_snmp() if args.proto == "tcp" else None

    threads = []
    if phases:
        if args.proto == "udp":
            threads.append(threading.Thread(
                target=udp_sender, args=(args, args.run, hid, t0, phases, st)))
        else:
            threads.append(threading.Thread(
                target=tcp_sender, args=(args, args.run, hid, t0, phases, st, tcp_out)))
    if args.probe:
        threads.append(threading.Thread(
            target=probe_runner, args=(args, args.run, hid, t0, duration, probe_out)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    snmp_after = read_tcp_snmp() if args.proto == "tcp" else None

    result = {
        "run": args.run,
        "host": host,
        "label": args.label,
        "proto": args.proto,
        "t0": t0,
        "phases": [list(p) for p in phases],
        "duration": duration,
        "sent_pkts": st.pkts,
        "sent_bytes": st.bytes,
        "seq_end": st.last_seq + 1,
        "send_errors": st.errors,
        "sent_by_sec": {str(k): v for k, v in st.by_sec.items()},
        "first_seq_by_sec": {str(k): v for k, v in st.first_seq_by_sec.items()},
        "probe": probe_out or None,
        "tcp": None,
    }
    if args.proto == "tcp":
        tcp = {"error": tcp_out.get("error", "")}
        if snmp_before and snmp_after:
            tcp["retrans"] = snmp_after["retrans"] - snmp_before["retrans"]
            tcp["outsegs"] = snmp_after["outsegs"] - snmp_before["outsegs"]
        result["tcp"] = tcp

    final = os.path.join(obs_dir, "sent_run%d_%s.json" % (args.run, host))
    tmp = final + ".tmp"
    with open(tmp, "w") as f:
        json.dump(result, f)
    os.replace(tmp, final)

    secs = max(end, 1e-9)
    print("enviado: %d pacotes, %d bytes (%.2f Mbps em média sobre %.0f s), erros de envio: %d" % (
        st.pkts, st.bytes, st.bytes * 8 / secs / 1e6, end, st.errors))
    if probe_out:
        got = [s[1] for s in probe_out["samples"] if s[1] is not None]
        if got:
            print("sondas: %d enviadas, %d respondidas, RTT médio %.1f ms, máx %.1f ms" % (
                probe_out["sent"], len(got), sum(got) / len(got), max(got)))
        else:
            print("sondas: %d enviadas, nenhuma respondida" % probe_out["sent"])
    if result["tcp"]:
        print("TCP: %s" % result["tcp"])
    print("resultado gravado em %s" % final)


if __name__ == "__main__":
    main()

