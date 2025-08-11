#!/usr/bin/env python3

# Kullanım Örnekleri:
#   python interniaDiscover.py 192.168.1.0/24 -> Çıktı vermez, sessiz çalışır.
#   python interniaDiscover.py 192.168.1.65 --vv --packet-trace --live 
#   python interniaDiscover.py 10.0.0.0/16 --preset stealth --json out.json 
#   python interniaDiscover.py targets.txt --packet-trace --decoys 198.51.100.10,203.0.113.7,ME
#   python interniaDiscover.py 203.0.113.0/24 --methods PS --ps-ports 443,8443 --spoof-mac 0

import argparse, subprocess, sys, json, csv, shutil, re, os
from datetime import datetime
from typing import List, Dict, Tuple, Optional

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
    C_OK = Fore.GREEN
    C_WARN = Fore.YELLOW
    C_ERR = Fore.RED
    C_INFO = Fore.CYAN
    C_DIM = Style.DIM
    C_RST = Style.RESET_ALL
except Exception:
    C_OK = C_WARN = C_ERR = C_INFO = C_DIM = C_RST = ""

GREPABLE_HOST_RE = re.compile(r'^Host:\s+(\S+)\s+\((.*?)\)\s+Status:\s+Up', re.I)

METHOD_FLAGS = {
    "PE": ["-PE"],             # ICMP Echo
    "PP": ["-PP"],             # ICMP Timestamp
    "PM": ["-PM"],             # ICMP Address Mask
    "PS": ["-PS"],             # TCP SYN (port list eklenir)
    "PA": ["-PA"],             # TCP ACK (port list eklenir)
    "PU": ["-PU"],             # UDP    (port list eklenir)
    "PR": ["-PR"],             # ARP (aynı subnet)
    "PO": ["-PO"],             # IP Protocol (proto list eklenir)
}

METHOD_EXPLAIN = {
    "PE": "ICMP Echo Ping — Type 8 gönderir, Type 0 yanıt bekler (klasik ping).",
    "PP": "ICMP Timestamp — Type 13 gönderir, Type 14 yanıt bekler (bazı yerlerde echo kapalıyken açık olabilir).",
    "PM": "ICMP Address Mask — Type 17/18 (modern ortamlarda nadir yanıt).",
    "PS": "TCP SYN Ping — seçili porta SYN; SYN/ACK veya RST gelirse host alive.",
    "PA": "TCP ACK Ping — ACK; RST gelirse host alive (stateful FW arkasında işe yarar).",
    "PU": "UDP Ping — porta UDP; ICMP Port Unreachable gelirse host alive.",
    "PR": "ARP Ping — aynı LAN’da MAC sorar; cevap varsa cihaz kesin canlı.",
    "PO": "IP Protocol Ping — belirttiğin IP protokol numarasıyla ham paket yollar (örn. 47=GRE).",
}

DEFAULT_PS_PORTS = "22,80,443,3389"
DEFAULT_PA_PORTS = "80,443"
DEFAULT_PU_PORTS = "53,123"
DEFAULT_PO_PROTOS = "1,6,17,47"  # ICMP,TCP,UDP,GRE

def which_nmap() -> str:
    exe = shutil.which("nmap")
    if not exe:
        print(f"{C_ERR}[!] Nmap bulunamadı. Kurulum: https://nmap.org/download.html{C_RST}", file=sys.stderr)
        sys.exit(1)
    return exe

def narrate(msg: str, level="info"):
    color = {"info": C_INFO, "ok": C_OK, "warn": C_WARN, "err": C_ERR, "dim": C_DIM}.get(level, "")
    print(color + msg + C_RST)

def build_nmap_cmd(nmap_exe: str,
                   target: str,
                   method: str,
                   evasion: Dict[str, Optional[str]],
                   ps_ports: str, pa_ports: str, pu_ports: str, po_protos: str,
                   very_verbose: bool, packet_trace: bool, stats_every: Optional[str]) -> List[str]:
    # -n: DNS yok taramayı yavaşlatmasın | -oG -: grepable stdout 
    # | --disable-arp-ping: davranışı netleştir (PR seçilirse ARP açıkça kullanılır, parametre olarak özellikle belirtilmesi gerek.)
    cmd = [nmap_exe, "-sn", "-n", "-oG", "-", "--disable-arp-ping"]

    # Verbose/Reason/Packet trace
    cmd += (["-vv", "--reason"] if very_verbose else ["-v", "--reason"])
    if packet_trace:
        cmd += ["--packet-trace"]
    if stats_every:
        cmd += ["--stats-every", stats_every]

    # Yöntem flag'ı ve port/proto ekleri
    if method == "PS":
        cmd += ["-PS" + ps_ports]
    elif method == "PA":
        cmd += ["-PA" + pa_ports]
    elif method == "PU":
        cmd += ["-PU" + pu_ports]
    elif method == "PO":
        cmd += ["-PO" + po_protos]
    else:
        cmd += METHOD_FLAGS[method]

    # Evasion & görünürlük azaltma
    if evasion.get("timing"):
        cmd += [evasion["timing"]]  # -T0..-T5
    if evasion.get("scan_delay"):
        cmd += ["--scan-delay", evasion["scan_delay"]]
    if evasion.get("max_rate"):
        cmd += ["--max-rate", evasion["max_rate"]]
    if evasion.get("decoys"):
        cmd += ["-D", evasion["decoys"]]
    if evasion.get("spoof_mac"):
        cmd += ["--spoof-mac", evasion["spoof_mac"]]
    if evasion.get("src_ip"):
        cmd += ["-S", evasion["src_ip"]]
    if evasion.get("iface"):
        cmd += ["-e", evasion["iface"]]
    if evasion.get("fragment"):
        cmd += ["-f"]
    if evasion.get("mtu"):
        cmd += ["--mtu", evasion["mtu"]]
    if evasion.get("proxies"):
        cmd += ["--proxies", evasion["proxies"]]
    if evasion.get("defeat_rst"):
        cmd += ["--defeat-rst-ratelimit"]

    cmd.append(target)
    return cmd

def run_nmap_stream(cmd: List[str], live: bool) -> Tuple[str, str, int]:
    """
    Deadlock fix: stderr -> STDOUT birleştirilir; tek borudan tüketilir.
    Live ise satır satır anlık basılır.
    """
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # <<< ÖNEMLİ: deadlock olmaz
            text=True,
            bufsize=1
        )
    except Exception as e:
        return ("", str(e), 1)

    out_buf = []
    # stdout'u satır satır tüket
    for line in p.stdout:
        out_buf.append(line)
        if live:
            print(C_DIM + line.rstrip() + C_RST)

    rc = p.wait()
    return ("".join(out_buf), "", rc)

def parse_grepable(output: str) -> List[Tuple[str, str]]:
    up = []
    for line in output.splitlines():
        m = GREPABLE_HOST_RE.match(line.strip())
        if m:
            ip = m.group(1)
            host = m.group(2) or ""
            up.append((ip, host))
    return up

def merge_results(agg: Dict[str, Dict], found: List[Tuple[str, str]], method: str):
    ts = datetime.utcnow().isoformat() + "Z"
    for ip, host in found:
        if ip not in agg:
            agg[ip] = {
                "ip": ip,
                "hostname": host if host != "" else None,
                "first_seen": ts,
                "methods": set([method]),
                "last_seen": ts
            }
        else:
            if host and not agg[ip]["hostname"]:
                agg[ip]["hostname"] = host
            agg[ip]["methods"].add(method)
            agg[ip]["last_seen"] = ts

def write_json(path: str, agg: Dict[str, Dict]):
    data = []
    for ip, rec in sorted(agg.items()):
        data.append({
            "ip": rec["ip"],
            "hostname": rec["hostname"],
            "first_seen": rec["first_seen"],
            "last_seen": rec["last_seen"],
            "methods": sorted(list(rec["methods"]))
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"scan_time_utc": datetime.utcnow().isoformat() + "Z",
                   "total_up": len(data),
                   "hosts": data}, f, indent=2)

def write_csv(path: str, agg: Dict[str, Dict]):
    rows = []
    for ip, rec in sorted(agg.items()):
        rows.append({
            "ip": rec["ip"],
            "hostname": rec["hostname"] or "",
            "first_seen": rec["first_seen"],
            "last_seen": rec["last_seen"],
            "methods": "|".join(sorted(list(rec["methods"])))
        })
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ip", "hostname", "first_seen", "last_seen", "methods"])
        w.writeheader()
        w.writerows(rows)

def parse_methods_arg(s: str) -> List[str]:
    s = s.strip().lower()
    if s == "all":
        return ["PE","PP","PM","PS","PA","PU","PR","PO"]
    given = [x.strip().upper() for x in s.split(",") if x.strip()]
    for m in given:
        if m not in METHOD_FLAGS:
            raise ValueError(f"Bilinmeyen method: {m}. Geçerli: {','.join(METHOD_FLAGS.keys())} veya all")
    return given

def apply_preset(args):
    if args.preset is None:
        return
    p = args.preset.lower()
    narrate(f"[*] Preset: {p}", "info")
    if p == "fast":
        if not args.methods: args.methods = "PE,PS,PR"
        if not any([args.T0,args.T1,args.T2,args.T3,args.T4,args.T5]):
            args.T3 = True
        if not args.max_rate: args.max_rate = "200"
    elif p == "stealth":
        if not args.methods: args.methods = "PS,PA,PU"
        args.T1 = True
        args.scan_delay = args.scan_delay or "200ms"
        args.max_rate = args.max_rate or "30"
        if args.fragment is False or args.fragment is None:
            args.fragment = True
    elif p == "thorough":
        args.methods = "all"
        args.T2 = True
        args.scan_delay = args.scan_delay or "100ms"
        args.max_rate = args.max_rate or "80"
    else:
        narrate(f"[!] Bilinmeyen preset: {p}", "warn")

def main():
    banner="""
_ _  _ ___ ____ ____ _  _ _ ____ ___  _ ____ ____ ____ _  _ ____ ____ 
| |\\ |  |  |___ |__/ |\\ | | |__| |  \\ | [__  |    |  | |  | |___ |__/ 
| | \\|  |  |___ |  \\ | \\| | |  | |__/ | ___] |___ |__|  \\/  |___ |  \\
                                                                                                                                                                        
    """
    print(Fore.RED+banner+Fore.RESET)
    ap = argparse.ArgumentParser(
        prog="interniaDiscover.py",
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "Hızlı başlangıç:\n\n"
            "  python interniaDiscover.py 192.168.1.0/24\n"
            "  python interniaDiscover.py 192.168.1.65 --vv --packet-trace --live\n"
            "  python interniaDiscover.py 10.0.0.0/16 --preset stealth --json out.json\n"
        )
    )
    ap.add_argument("target", help="Hedef: CIDR (192.168.1.0/24), tek IP, IP aralığı veya targets.txt")

    # Presetler
    ap.add_argument("--preset", choices=["fast","stealth","thorough"], help=(
        "fast: PE,PS,PR; -T3; --max-rate 200\n"
        "stealth: PS,PA,PU; -T1; --scan-delay 200ms; --max-rate 30; --fragment\n"
        "thorough: all; -T2; --scan-delay 100ms; --max-rate 80\n"
    ))

    # Yöntemler
    ap.add_argument("--methods", default=None, help="all veya virgüllü liste: PE,PP,PM,PS,PA,PU,PR,PO")
    ap.add_argument("--explain", action="store_true", help="Seçilen yöntemleri taramadan önce kısaca açıkla")

    # Port/Proto
    ap.add_argument("--ps-ports", default=DEFAULT_PS_PORTS, help=f"PS için portlar (vars: {DEFAULT_PS_PORTS})")
    ap.add_argument("--pa-ports", default=DEFAULT_PA_PORTS, help=f"PA için portlar (vars: {DEFAULT_PA_PORTS})")
    ap.add_argument("--pu-ports", default=DEFAULT_PU_PORTS, help=f"PU için portlar (vars: {DEFAULT_PU_PORTS})")
    ap.add_argument("--po-protos", default=DEFAULT_PO_PROTOS, help=f"PO için IP protoları (vars: {DEFAULT_PO_PROTOS})")

    # Verbose & Trace
    ap.add_argument("--vv", action="store_true", help="Daha detaylı: Nmap -vv + --reason")
    ap.add_argument("--packet-trace", action="store_true", help="--packet-trace (paketleri satır satır göster)")
    ap.add_argument("--live", action="store_true", help="Çıktıyı anlık akış olarak bas")
    ap.add_argument("--stats-every", help="Nmap ilerleme çıktısı (örn: 2s)")

    # Evasion
    ap.add_argument("-T0", dest="T0", action="store_true", help="Timing: paranoid")
    ap.add_argument("-T1", dest="T1", action="store_true", help="Timing: sneaky")
    ap.add_argument("-T2", dest="T2", action="store_true", help="Timing: polite")
    ap.add_argument("-T3", dest="T3", action="store_true", help="Timing: normal")
    ap.add_argument("-T4", dest="T4", action="store_true", help="Timing: aggressive")
    ap.add_argument("-T5", dest="T5", action="store_true", help="Timing: insane")
    ap.add_argument("--scan-delay", help="Her paket arası gecikme (örn: 200ms)")
    ap.add_argument("--max-rate", help="Saniyede paket limiti (örn: 50)")
    ap.add_argument("--decoys", help="Decoy IP listesi (örn: 198.51.100.10,203.0.113.7,ME)")
    ap.add_argument("--spoof-mac", help="MAC sahtele (örn: 0, Apple, 00:11:22:33:44:55)")
    ap.add_argument("--src-ip", help="Kaynak IP spoof")
    ap.add_argument("--iface", help="Ağ arayüzü (örn: eth0)")
    ap.add_argument("--fragment", action="store_true", help="Paketleri parçala (-f)")
    ap.add_argument("--mtu", help="Özel MTU (örn: 8)")
    ap.add_argument("--proxies", help="HTTP/SOCKS proxy zinciri")
    ap.add_argument("--defeat-rst", action="store_true", help="--defeat-rst-ratelimit")

    # Çıktı
    ap.add_argument("--json", help="JSON çıktı yolu")
    ap.add_argument("--csv", help="CSV çıktı yolu")

    # Kontrol
    ap.add_argument("--dry-run", action="store_true", help="Komutları çalıştırma, sadece göster")
    ap.add_argument("--quiet", action="store_true", help="Özet mod")

    args = ap.parse_args()

    # Preset uygula
    apply_preset(args)

    # Varsayılan: all
    methods_arg = args.methods or "all"
    try:
        methods = parse_methods_arg(methods_arg)
    except ValueError as e:
        narrate("[!] " + str(e), "err")
        sys.exit(2)

    # Timing seçimi
    timing = None
    for t in ["T0","T1","T2","T3","T4","T5"]:
        if getattr(args, t):
            timing = "-" + t
            break

    very_verbose = bool(args.vv)
    packet_trace = bool(args.packet_trace)
    live = bool(args.live)
    stats_every = args.stats_every

    # Evasion dict
    evasion = {
        "timing": timing,
        "scan_delay": args.scan_delay,
        "max_rate": args.max_rate,
        "decoys": args.decoys,
        "spoof_mac": args.spoof_mac,
        "src_ip": args.src_ip,
        "iface": args.iface,
        "fragment": args.fragment,
        "mtu": args.mtu,
        "proxies": args.proxies,
        "defeat_rst": args.defeat_rst
    }

    nmap_exe = which_nmap()

    # Üst bilgi
    if not args.quiet:
        narrate(f"[*] Hedef(ler): {args.target}", "info")
        narrate(f"[*] Yöntemler: {', '.join(methods)}", "info")
        if args.explain:
            for m in methods:
                narrate(f"    - {m}: {METHOD_EXPLAIN[m]}", "dim")
        ev_short = ", ".join([f"{k}={v}" for k,v in evasion.items() if v]) if any(evasion.values()) else "yok"
        narrate(f"[*] Evasion: {ev_short}", "info")
        narrate(f"[*] Verbose: {'-vv + --reason' if very_verbose else '-v + --reason'}; "
                f"Packet-trace: {'açık' if packet_trace else 'kapalı'}; "
                f"Live: {'açık' if live else 'kapalı'}; "
                f"Stats: {stats_every or 'kapalı'}", "info")

    aggregate: Dict[str, Dict] = {}
    method_errors: Dict[str, str] = {}

    # Her yöntemi ayrı koştur
    for m in methods:
        if not args.quiet:
            narrate(f"\n[+] {m} başlıyor → {METHOD_EXPLAIN[m]}", "ok")

        cmd = build_nmap_cmd(nmap_exe, args.target, m, evasion,
                             args.ps_ports, args.pa_ports, args.pu_ports, args.po_protos,
                             very_verbose, packet_trace, stats_every)

        # Komutu net göster
        narrate("[cmd] " + " ".join(cmd), "dim")

        if args.dry_run:
            narrate(f"[i] Dry-run: {m} çalıştırılmadı.", "warn")
            continue

        out, err, rc = run_nmap_stream(cmd, live=live)

        if rc != 0:
            method_errors[m] = (err.strip() or f"nmap exit code {rc}")
            narrate(f"[!] {m} hata: {method_errors[m]}", "err")
            continue

        hits = parse_grepable(out)
        merge_results(aggregate, hits, m)
        upcount = len(hits)

        if not args.quiet:
            if upcount > 0:
                narrate(f"[+] {m} bitti: {upcount} host canlı bulundu.", "ok")
                for ip, host in hits:
                    hn = host or "-"
                    narrate(f"    • {ip}\t(hostname: {hn})", "dim")
            else:
                narrate(f"[-] {m} bitti: bu yöntemle canlı host bulunamadı.", "warn")

    # Özet
    if not args.quiet:
        narrate("\n=== ÖZET ===", "info")
        narrate(f"Toplam benzersiz canlı host: {len(aggregate)}", "ok")
        if method_errors:
            narrate("Hata veren yöntem(ler): " + ", ".join(method_errors.keys()), "warn")

        for ip, rec in sorted(aggregate.items()):
            methods_used = ",".join(sorted(rec["methods"]))
            hn = rec["hostname"] or "-"
            print(f"{ip}\t{hn}\tmethods={methods_used}")

    # Dosya yaz
    if args.json:
        write_json(args.json, aggregate)
        narrate(f"[+] JSON yazıldı: {args.json}", "ok")
    if args.csv:
        write_csv(args.csv, aggregate)
        narrate(f"[+] CSV yazıldı: {args.csv}", "ok")

    sys.exit(0 if len(aggregate) > 0 or args.dry_run else 1)

if __name__ == "__main__":
    main()
