#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Örnekler:
  python interniaMap.py 192.168.1.65                   # top-1000 TCP (varsayılan)
  python interniaMap.py 192.168.1.0/24 --udp           # top-1000 TCP + UDP
  python interniaMap.py 192.168.1.65 -p 80,443,5173    # özel port listesi
  python interniaMap.py 192.168.1.65 --top-ports 2000  # en yaygın olarak kullanılan ilk 2000 port
  python interniaMap.py 192.168.1.65 --popular web     # gömülü popüler set
  python interniaMap.py 192.168.1.65 --syn -sV         # SYN + servis/versiyon
  python interniaMap.py targets.txt --os               # dosyadan hedef + OS tespit (auto -iL)
  python interniaMap.py 192.168.1.65 --json out.json --csv out.csv
  python interniaMap.py 192.168.1.65 --vv --packet-trace --stats-every 2s
  python interniaMap.py 192.168.1.65 --preset stealth  # evasion preset

Notlar:
- Varsayılan top-1000 TCP. UDP ve diğer teknikler isteğe bağlı.
- Çıktı: konsol (varsayılan) + opsiyonel JSON/CSV.
- Nmap gerektirir (PATH üzerinde olmalı).
"""

import argparse, subprocess, sys, json, csv, shutil, os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET
from urllib.request import urlopen, Request
from urllib.parse import quote
from urllib.error import URLError, HTTPError
import requests
from pathlib import Path


# ==== Renkler ====
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

# ==== Popüler port setleri (örnek) ====
POPULAR_PORT_SETS: Dict[str, str] = {
    # HTTP(S)/Proxy/Webapp/DevOps
    "web": "80,81,88,300,443,444,4443,8080,8081,8088,8443,8000,8008,8888,9000,9200,5601,9090,9091,9443",
    # Admin/Remote
    "remote": "22,23,25,110,143,389,445,465,587,993,995,3306,3389,5432,5900,5985,5986,6379,8089,27017",
    # OT/IoT/Discovery
    "iot": "53,67,68,69,123,137,138,139,161,162,1900,5353,47808",
    # Full mini-mix
    "mixed": "22,53,80,123,135,139,161,389,443,445,500,587,631,873,902,903,1194,1433,1521,2049,2375,2376,3000,3128,3306,3389,4444,5000,5001,5044,5432,5601,5672,5900,5985,5986,6379,7001,7002,7199,8000,8001,8008,8080,8081,8082,8088,8140,8161,8443,8500,8529,8570,8888,9000,9042,9090,9200,9300,9443,10000,11211,27017,27018,27019",
}

# ==== Yardımcılar ====
def narrate(msg: str, level: str = "info") -> None:
    color = {"info": C_INFO, "ok": C_OK, "warn": C_WARN, "err": C_ERR, "dim": C_DIM}.get(level, "")
    print(color + msg + C_RST)

def which_nmap() -> str:
    exe = shutil.which("nmap")
    if not exe:
        print(f"{C_ERR}[!] Nmap bulunamadı. Kurulum: https://nmap.org/download.html{C_RST}", file=sys.stderr)
        sys.exit(1)
    return exe

# ==== Nmap komutu kurucu ====
def build_nmap_cmd(
    nmap_exe: str,
    target: str,
    ports: Optional[str],
    top_ports: Optional[str],
    popular: Optional[str],
    tcp_modes: Dict[str, bool],
    do_udp: bool,
    service_version: bool,
    os_detect: bool,
    aggressive: bool,
    very_verbose: bool,
    packet_trace: bool,
    stats_every: Optional[str],
    evasion: Dict[str, Optional[str]],
) -> List[str]:
    cmd = [nmap_exe, "-n", "-oX", "-"]
    cmd += (["-vv", "--reason"] if very_verbose else ["-v", "--reason"])
    if packet_trace:
        cmd += ["--packet-trace"]
    if stats_every:
        cmd += ["--stats-every", stats_every]

    if ports:
        cmd += ["-p", ports]
    elif popular:
        preset = POPULAR_PORT_SETS.get(popular.lower())
        if not preset:
            raise SystemExit(f"[!] Bilinmeyen --popular set: {popular}. Mevcut: {', '.join(POPULAR_PORT_SETS)}")
        cmd += ["-p", preset]
    elif top_ports:
        cmd += ["--top-ports", top_ports]
    else:
        cmd += ["--top-ports", "1000"]

    if tcp_modes.get("syn"):
        cmd += ["-sS"]
    elif tcp_modes.get("connect") or not any(tcp_modes.values()):
        cmd += ["-sT"]

    if tcp_modes.get("ack"): cmd += ["-sA"]
    if tcp_modes.get("fin"): cmd += ["-sF"]
    if tcp_modes.get("null"): cmd += ["-sN"]
    if tcp_modes.get("xmas"): cmd += ["-sX"]
    if tcp_modes.get("maimon"): cmd += ["-sM"]
    if tcp_modes.get("window"): cmd += ["-sW"]

    if do_udp:
        cmd += ["-sU"]

    if service_version:
        cmd += ["-sV"]
    if os_detect:
        cmd += ["-O"]
    if aggressive:
        cmd += ["-A"]

    if evasion.get("timing"): cmd += [evasion["timing"]]
    if evasion.get("scan_delay"): cmd += ["--scan-delay", evasion["scan_delay"]]
    if evasion.get("max_rate"): cmd += ["--max-rate", evasion["max_rate"]]
    if evasion.get("min_rate"): cmd += ["--min-rate", evasion["min_rate"]]
    if evasion.get("decoys"): cmd += ["-D", evasion["decoys"]]
    if evasion.get("spoof_mac"): cmd += ["--spoof-mac", evasion["spoof_mac"]]
    if evasion.get("src_ip"): cmd += ["-S", evasion["src_ip"]]
    if evasion.get("iface"): cmd += ["-e", evasion["iface"]]
    if evasion.get("fragment"): cmd += ["-f"]
    if evasion.get("mtu"): cmd += ["--mtu", evasion["mtu"]]
    if evasion.get("proxies"): cmd += ["--proxies", evasion["proxies"]]
    if evasion.get("defeat_rst"): cmd += ["--defeat-rst-ratelimit"]

    # target dosyası mı?
    try:
        if Path(target).is_file():
            cmd += ["-iL", target]
        else:
            cmd.append(target)
    except Exception:
        cmd.append(target)

    return cmd

# ==== Nmap çıktısı (XML) ayrıştırıcı ====
def parse_nmap_xml(xml_text: str) -> Dict:
    """Nmap XML stdout'tan özet JSON yapısı döndür."""
    root = ET.fromstring(xml_text)
    scan = {
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "nmaprun": root.attrib,
        "hosts": [],
    }

    for host in root.findall("host"):
        status = host.find("status")
        addr_el = host.find("address")
        addr = addr_el.attrib.get("addr") if addr_el is not None else None
        hostname = None
        hn_parent = host.find("hostnames")
        if hn_parent is not None:
            hn = hn_parent.find("hostname")
            if hn is not None:
                hostname = hn.attrib.get("name")

        h = {
            "ip": addr,
            "hostname": hostname,
            "status": status.attrib.get("state") if status is not None else None,
            "ports": [],
            "os": None,
        }

        # Ports
        ports = host.find("ports")
        if ports is not None:
            for p in ports.findall("port"):
                proto = p.attrib.get("protocol")
                portid = int(p.attrib.get("portid"))
                state_el = p.find("state")
                state = state_el.attrib.get("state") if state_el is not None else None
                reason = state_el.attrib.get("reason") if state_el is not None else None
                service_el = p.find("service")
                service = None
                if service_el is not None:
                    service = {
                        "name": service_el.attrib.get("name"),
                        "product": service_el.attrib.get("product"),
                        "version": service_el.attrib.get("version"),
                        "extrainfo": service_el.attrib.get("extrainfo"),
                        "tunnel": service_el.attrib.get("tunnel"),
                        "proto": service_el.attrib.get("proto"),
                        "ostype": service_el.attrib.get("ostype"),
                        "method": service_el.attrib.get("method"),
                        "conf": service_el.attrib.get("conf"),
                    }
                h["ports"].append({
                    "proto": proto,
                    "port": portid,
                    "state": state,
                    "reason": reason,
                    "service": service,
                })
        
        # OS
        os_el = host.find("os")
        if os_el is not None:
            matches = []
            for m in os_el.findall("osmatch"):
                matches.append({
                    "name": m.attrib.get("name"),
                    "accuracy": m.attrib.get("accuracy"),
                    "line": m.attrib.get("line"),
                })
            h["os"] = {
                "matches": matches
            }

        scan["hosts"].append(h)

    return scan

# ==== Çıktı yazıcılar ====
def write_json(path: str, data: Dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_csv(path: str, data: Dict) -> None:
    rows = []
    for h in data.get("hosts", []):
        for p in h.get("ports", []):
            service = p.get("service") or {}
            rows.append({
                "ip": h.get("ip"),
                "hostname": h.get("hostname") or "",
                "proto": p.get("proto"),
                "port": p.get("port"),
                "state": p.get("state"),
                "reason": p.get("reason") or "",
                "service_name": service.get("name") or "",
                "product": service.get("product") or "",
                "version": service.get("version") or "",
                "extrainfo": service.get("extrainfo") or "",
            })
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "ip","hostname","proto","port","state","reason","service_name","product","version","extrainfo"
        ])
        w.writeheader()
        w.writerows(rows)

def search_cve_nvd(query, max_items=5):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": max_items}
    try:
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return [{"id": "NVD_ERROR", "summary": f"NVD sorgusu başarısız: {str(e)[:160]}"}]
    vulns = []
    for item in data.get("vulnerabilities", []):
        cve_id = item.get("cve", {}).get("id")
        descs = item.get("cve", {}).get("descriptions", [])
        desc = descs[0]["value"] if descs else ""
        if cve_id:
            vulns.append({"id": cve_id, "summary": desc})
    return vulns

def attach_cves(parsed: Dict, max_items: int = 5) -> None:
    for h in parsed.get("hosts", []):
        for p in h.get("ports", []):
            if p.get("state") != "open":
                continue
            svc = p.get("service") or {}
            product = (svc.get("product") or svc.get("name") or "").strip()
            version = (svc.get("version") or "").strip()
            if not product:
                continue  # banner yoksa arama yok
            q = (product + (" " + version if version else "")).strip()
            cves = search_cve_nvd(q)
            if not cves:
                continue
            slim = []
            for it in cves[:max_items]:
                cve_id = it.get("id") or it.get("cve")
                summary = it.get("summary") or it.get("description") or ""
                if cve_id:
                    slim.append({"id": cve_id, "summary": summary[:200]})
            if slim:
                p["cve_matches"] = slim


# ==== Nmap çalıştırıcı (stream) ====
def run_nmap_stream(cmd: List[str], live: bool) -> Tuple[str, str, int]:
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,   # <-- STDERR ayrı
            text=True,
            bufsize=1
        )
    except Exception as e:
        return ("", str(e), 1)

    out_buf: List[str] = []
    for line in p.stdout:
        out_buf.append(line)
        if live:
            # XML satırlarını dim bas
            print(C_DIM + line.rstrip() + C_RST)
    rc = p.wait()

    # Süreç tamamlandıktan sonra STDERR'i oku
    err_text = ""
    if p.stderr:
        try:
            err_text = p.stderr.read()
        except Exception:
            err_text = ""

    return ("".join(out_buf), err_text, rc)

# ==== Preset uygula ====
def apply_preset(args: argparse.Namespace) -> None:
    if args.preset is None:
        return
    p = args.preset.lower()
    narrate(f"[*] Preset: {p}", "info")
    if p == "fast":
        # hızlı sonuç için top-ports 200 + T4
        if not args.top_ports and not args.ports and not args.popular:
            args.top_ports = "200"
        if not any([args.T0,args.T1,args.T2,args.T3,args.T4,args.T5]):
            args.T4 = True
        args.max_rate = args.max_rate or "1000"
    elif p == "stealth":
        args.T1 = True
        args.scan_delay = args.scan_delay or "200ms"
        args.max_rate = args.max_rate or "50"
        if not args.syn:
            args.syn = True
        if args.fragment is False or args.fragment is None:
            args.fragment = True
    elif p == "thorough":
        # kapsamlı: -sV + daha fazla top-ports + T2
        args.service_version = True
        if not args.top_ports and not args.ports and not args.popular:
            args.top_ports = "2000"
        args.T2 = True
        args.scan_delay = args.scan_delay or "100ms"
        args.max_rate = args.max_rate or "200"
    else:
        narrate(f"[!] Bilinmeyen preset: {p}", "warn")

# ==== Argümanlar ====
def build_cli() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="interniaMap.py (patched XML/STDERR handling)",
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "Hızlı başlangıç:\n"
            "  python interniaMap.py 192.168.1.65 -p 80,443 -sV\n"
            "  python interniaMap.py 192.168.1.0/24 --udp --top-ports 1000\n"
            "  python interniaMap.py 192.168.1.65 --preset stealth --json out.json\n"
            "  python interniaMap.py 192.168.1.65                   # top-1000 TCP (varsayılan)\n"
            "  python interniaMap.py 192.168.1.0/24 --udp           # top-1000 TCP + UDP\n"
            "  python interniaMap.py 192.168.1.65 -p 80,443,5173    # özel port listesi\n"
            "  python interniaMap.py 192.168.1.65 --top-ports 2000  # ilk 2000 port\n"
            "  python interniaMap.py 192.168.1.65 --popular web     # gömülü popüler set\n"
            "  python interniaMap.py 192.168.1.65 --syn -sV         # SYN + servis/versiyon\n"
            "  python interniaMap.py targets.txt --os               # dosyadan hedef + OS tespit \n"
            "  python interniaMap.py 192.168.1.65 --json out.json --csv out.csv\n"
            "  python interniaMap.py 192.168.1.65 --vv --packet-trace --stats-every 2s\n"
            "  python interniaMap.py 192.168.1.65 --preset stealth  # evasion preset\n"
            )
    )

    ap.add_argument("target", help="Hedef: tek IP/domain, CIDR (192.168.1.0/24) veya targets.txt")

    # Presetler
    ap.add_argument("--preset", choices=["fast","stealth","thorough"], help=(
        "fast: top-200; -T4; --max-rate 1000\n"
        "stealth: -T1; --scan-delay 200ms; --max-rate 50; --fragment\n"
        "thorough: -sV; top-2000; -T2; --scan-delay 100ms; --max-rate 200\n"
    ))

    # Port kapsamı
    ap.add_argument("-p", "--ports", help="Özel port(lar) (örn: 80,443,5173 veya 1-65535)")
    ap.add_argument("--top-ports", dest="top_ports", help="İlk N port (örn: 1000)")
    ap.add_argument("--popular", help=f"Popüler set adı (mevcut: {', '.join(POPULAR_PORT_SETS)})")

    # Teknikler
    g_tcp = ap.add_argument_group("TCP tarama teknikleri")
    g_tcp.add_argument("--connect", action="store_true", help="TCP connect() (varsayılan)")
    g_tcp.add_argument("--syn", action="store_true", help="TCP SYN half-open")
    g_tcp.add_argument("--ack", action="store_true", help="TCP ACK (firewall durumu)")
    g_tcp.add_argument("--fin", action="store_true", help="TCP FIN")
    g_tcp.add_argument("--null", action="store_true", help="TCP NULL")
    g_tcp.add_argument("--xmas", action="store_true", help="TCP Xmas")
    g_tcp.add_argument("--maimon", action="store_true", help="TCP Maimon")
    g_tcp.add_argument("--window", action="store_true", help="TCP Window")

    ap.add_argument("--udp", action="store_true", help="UDP taramasını da ekle (-sU)")

    # Derinlik
    ap.add_argument("-sV", "--service-version", action="store_true", help="Servis/versiyon tespiti (-sV)")
    ap.add_argument("--os", dest="os_detect", action="store_true", help="OS tespiti (-O)")
    ap.add_argument("-A", "--aggressive", action="store_true", help="Agresif tarama (-A)")

    # Verbose/Trace/Stats
    ap.add_argument("--vv", action="store_true", help="-vv + --reason")
    ap.add_argument("--packet-trace", action="store_true", help="--packet-trace")
    ap.add_argument("--live", action="store_true", help="XML çıktıyı anlık akış olarak bas")
    ap.add_argument("--stats-every", help="İlerleme çıktısı (örn: 2s)")

    # Evasion & Timing
    ap.add_argument("-T0", dest="T0", action="store_true", help="Timing: paranoid")
    ap.add_argument("-T1", dest="T1", action="store_true", help="Timing: sneaky")
    ap.add_argument("-T2", dest="T2", action="store_true", help="Timing: polite")
    ap.add_argument("-T3", dest="T3", action="store_true", help="Timing: normal")
    ap.add_argument("-T4", dest="T4", action="store_true", help="Timing: aggressive")
    ap.add_argument("-T5", dest="T5", action="store_true", help="Timing: insane")
    ap.add_argument("--scan-delay", help="Her paket arası gecikme (örn: 200ms)")
    ap.add_argument("--max-rate", help="Saniyede paket üst limiti")
    ap.add_argument("--min-rate", help="Saniyede paket alt limiti")
    ap.add_argument("--decoys", help="Decoy IP listesi (örn: 198.51.100.10,203.0.113.7,ME)")
    ap.add_argument("--spoof-mac", help="MAC sahtele (örn: 0, Apple, 00:11:22:33:44:55)")
    ap.add_argument("--src-ip", help="Kaynak IP spoof")
    ap.add_argument("--iface", help="Ağ arayüzü (örn: eth0)")
    ap.add_argument("--fragment", action="store_true", help="Paketleri parçala (-f)")
    ap.add_argument("--mtu", help="Özel MTU (örn: 8)")
    ap.add_argument("--proxies", help="HTTP/SOCKS proxy zinciri")
    ap.add_argument("--defeat-rst", action="store_true", help="--defeat-rst-ratelimit")

    # Çıktılar
    ap.add_argument("--json", help="JSON çıktı yolu")
    ap.add_argument("--csv", help="CSV çıktı yolu")

    # CVE (minimal)
    ap.add_argument("--cve", action="store_true", help="Banner/servis bilgisinden NVD CVE araması yap")
    ap.add_argument("--cve-max", type=int, default=5, help="Her port için maksimum CVE sayısı (vars: 5)")

    # Kontrol
    ap.add_argument("--dry-run", action="store_true", help="Komutu çalıştırma, sadece göster")
    ap.add_argument("--quiet", action="store_true", help="Özet mod. Sadece JSON-CSV Çıktısı alınacaksa kullanılmalı.")

    return ap

# ==== Ana ====
def main():
    banner="""                         
_ _  _ ___ ____ ____ _  _ _ ____ _  _ ____ ___  
| |\\ |  |  |___ |__/ |\\ | | |__| |\\/| |__| |__] 
| | \\|  |  |___ |  \\ | \\| | |  | |  | |  | |    
                                                                                                   
    """                                                                                                            
    print(Fore.RED+banner+Fore.RESET)
    ap = build_cli()
    args = ap.parse_args()

    # Preset uygula
    apply_preset(args)

    # Timing seçimi
    timing = None
    for t in ["T0","T1","T2","T3","T4","T5"]:
        if getattr(args, t):
            timing = "-" + t
            break

    tcp_modes = {
        "connect": bool(args.connect),
        "syn": bool(args.syn),
        "ack": bool(args.ack),
        "fin": bool(args.fin),
        "null": bool(args.null),
        "xmas": bool(args.xmas),
        "maimon": bool(args.maimon),
        "window": bool(args.window),
    }

    # Evasion dict
    evasion = {
        "timing": timing,
        "scan_delay": args.scan_delay,
        "max_rate": args.max_rate,
        "min_rate": args.min_rate,
        "decoys": args.decoys,
        "spoof_mac": args.spoof_mac,
        "src_ip": args.src_ip,
        "iface": args.iface,
        "fragment": args.fragment,
        "mtu": args.mtu,
        "proxies": args.proxies,
        "defeat_rst": args.defeat_rst,
    }

    nmap_exe = which_nmap()

    if not args.quiet:
        narrate(f"[*] Hedef: {args.target}", "info")
        port_desc = args.ports or (f"top-{args.top_ports}" if args.top_ports else (f"popular:{args.popular}" if args.popular else "top-1000"))
        narrate(f"[*] Port kapsamı: {port_desc}", "info")
        narrate(f"[*] TCP modları: " + ", ".join([k for k,v in tcp_modes.items() if v]) if any(tcp_modes.values()) else "[*] TCP modları: connect (varsayılan)", "info")
        narrate(f"[*] UDP: {'açık' if args.udp else 'kapalı'}; sV: {'açık' if args.service_version else 'kapalı'}; OS: {'açık' if args.os_detect else 'kapalı'}; A: {'açık' if args.aggressive else 'kapalı'}", "info")
        ev_short = ", ".join([f"{k}={v}" for k,v in evasion.items() if v]) if any(evasion.values()) else "yok"
        narrate(f"[*] Evasion: {ev_short}", "info")
        narrate(f"[*] Verbose: {'-vv + --reason' if args.vv else '-v + --reason'}; Packet-trace: {'açık' if args.packet_trace else 'kapalı'}; Live: {'açık' if args.live else 'kapalı'}; Stats: {args.stats_every or 'kapalı'}", "info")

    cmd = build_nmap_cmd(
        nmap_exe=nmap_exe,
        target=args.target,
        ports=args.ports,
        top_ports=args.top_ports,
        popular=args.popular,
        tcp_modes=tcp_modes,
        do_udp=bool(args.udp),
        service_version=bool(args.service_version),
        os_detect=bool(args.os_detect),
        aggressive=bool(args.aggressive),
        very_verbose=bool(args.vv),
        packet_trace=bool(args.packet_trace),
        stats_every=args.stats_every,
        evasion=evasion,
    )


    # Bazı evasion kombinasyonları için -Pn öner
    if any([args.src_ip, args.decoys]) and not getattr(args, 'Pn_hint_shown', False):
        narrate('[i] Not: --src-ip/--decoys ile host discovery yanıtsız kalabilir; -Pn kullanmanız gerekebilir.', 'warn')
        args.Pn_hint_shown = True

    # Komutu göster
    narrate("[cmd] " + " ".join(cmd), "dim")

    if args.dry_run:
        narrate("[i] Dry-run: komut çalıştırılmadı.", "warn")
        sys.exit(0)

    out, err, rc = run_nmap_stream(cmd, live=bool(args.live))
    if rc != 0:
        msg = err.strip() or f"nmap exit code {rc}"
        narrate(f"[!] Hata: {msg}", "err")
        sys.exit(rc)

    # XML öncesi uyarıları göster ve stdout'u temizle
    if err.strip():
        narrate("[!] Uyarı:", "warn")
        print(err.strip())

    xml_text = out
    # stdout'ta XML'den önce gelen Warning/Notlar varsa kırp
    lt = xml_text.find("<")
    if lt > 0:
        junk = xml_text[:lt].strip()
        if junk:
            narrate("[!] Nmap uyarı/mesaj (stdout başı):", "warn")
            print(junk)
        xml_text = xml_text[lt:]

    # XML ayrıştır
    try:
        parsed = parse_nmap_xml(xml_text)
    except Exception as e:
        narrate(f"[!] XML ayrıştırma hatası: {e}", "err")
        # Ham çıktıyı debug için dosyaya dök
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        dump = f"nmap_raw_{ts}.xml"
        try:
            with open(dump, "w", encoding="utf-8") as f:
                f.write(xml_text)
            narrate(f"[i] Ham XML çıktısı kaydedildi: {dump}", "info")
        except Exception:
            pass
        sys.exit(2)

    # CVE zenginleştirme (minimal)
    if getattr(args, 'cve', False):
        if not getattr(args, 'service_version', False):
            narrate('[cve] -sV aktif edilmeden CVE taraması yapılamaz!.', 'warn')
        else:
            attach_cves(parsed, max_items=getattr(args, 'cve_max', 5))

    # Konsol özeti
    if not args.quiet:
        narrate("\n=== SONUÇ ===", "info")
        for h in parsed.get("hosts", []):
            if h.get("status") != "up":
                continue
            ip = h.get("ip")
            hn = h.get("hostname") or "-"
            opens = [p for p in h.get("ports", []) if p.get("state") == "open"]
            if opens:
                narrate(f"[+] {ip}\t(hostname: {hn}) — {len(opens)} açık port", "ok")
                for p in sorted(opens, key=lambda x:(x.get('proto'), x.get('port'))):
                    svc = p.get("service") or {}
                    svc_str = svc.get("name") or "?"
                    if svc.get("product") or svc.get("version") or svc.get("extrainfo"):
                        extra = " ".join(filter(None, [svc.get("product"), svc.get("version"), f"({svc.get('extrainfo')})" if svc.get('extrainfo') else None]))
                        svc_str += f" — {extra.strip()}"
                    print(f"    • {p.get('proto')}/{p.get('port')}\t{svc_str}")
                    if getattr(args, 'cve', False) and p.get('cve_matches'):
                        for c in p['cve_matches']:
                            print(f"        ↳ {c['id']}: {c['summary']}")
            else:
                narrate(f"[-] {ip}\t(hostname: {hn}) — açık port bulunamadı", "warn")
            # OS özetini göster
            if getattr(args, 'os_detect', False):
                osinfo = h.get("os") or {}
                matches = osinfo.get("matches") or []
                if matches:
                    # En muhtemel ilk 10.
                    top_matches = sorted(
                        matches,
                        key=lambda x: int(x.get("accuracy") or 0),
                        reverse=True
                    )[:10]
                    print("    -- OS tahminleri:")
                    for m in top_matches:
                        try:
                            acc = int(m.get("accuracy") or 0)
                        except:
                            acc = m.get("accuracy") or "?"
                        print(f"      - {m.get('name')} (~%{acc})")

    # Dosyalara yaz
    if args.json:
        write_json(args.json, parsed)
        narrate(f"[+] JSON yazıldı: {args.json}", "ok")
    if args.csv:
        write_csv(args.csv, parsed)
        narrate(f"[+] CSV yazıldı: {args.csv}", "ok")

    sys.exit(0)


if __name__ == "__main__":
    # Basit yasal uyarı (bir kere gösterilebilir; burada her çalıştırmada kısa tutuyoruz)
    if not os.environ.get("PS_SKIP_LEGAL"):
        narrate("[!] Yalnızca yetkili olduğun hedefleri tara. İzinsiz tarama hukuka aykırı olabilir.", "warn")
    main()
