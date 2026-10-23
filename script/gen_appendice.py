"""Genera l'appendice LaTeX con tutte le segnalazioni mostrate in dashboard per l'insieme di prova.

Fonte: validation/risultati/2026-10-01_<bersaglio>/{unified_security_report,core_findings}.json
Uso: python3 gen_appendice.py <radice-strumento> <file-tex-di-uscita>
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) / "validation" / "risultati"
OUT = Path(sys.argv[2])

TARGETS = [
    ("vampi", "VAmPI (modalità vulnerabile)"),
    ("dvapi", "DVAPI"),
    ("sadcloud", "sadcloud"),
]
MODULES = {
    "bola": "BOLA dinamica",
    "bola_static": "BOLA statica",
    "bopla": "BOPLA",
    "broken_authentication": "Broken Auth.",
    "bfla": "BFLA",
    "security_misconfiguration": "Sec.\\ Misconf.",
    "ssrf": "SSRF",
    "unrestricted_resource_consumption": "Res.\\ Cons.",
    "unsafe_consumption": "Unsafe Cons.",
}
SEV = {"CRITICAL": "Critica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Bassa", "INFO": "Info"}
SOURCE = {"CHECKOV": "Checkov", "SPECTRAL": "Spectral", "SEMGREP": "Semgrep"}


def esc(s: str) -> str:
    s = str(s or "")
    for a, b in [("\\", r"\textbackslash{}"), ("&", r"\&"), ("%", r"\%"), ("$", r"\$"), ("#", r"\#"),
                 ("_", r"\_"), ("{", r"\{"), ("}", r"\}"), ("~", r"\textasciitilde{}"),
                 ("^", r"\textasciicircum{}")]:
        s = s.replace(a, b)
    return s


def code(s: str) -> str:
    """Testo monospaziato che può andare a capo dopo / _ . -"""
    s = re.sub(r"([A-Za-z0-9]{10})(?=[A-Za-z0-9]{4})", "\\1\x00", str(s or ""))
    s = esc(s).replace("\x00", r"\allowbreak{}")
    for ch in ["/", r"\_", ".", "-"]:
        s = s.replace(ch, ch + r"\allowbreak{}")
    return r"\texttt{" + s + "}"


def short_path(p: str, target: str) -> str:
    p = (p or "").replace(f"data/test_targets/external/{target}/", "").lstrip("/")
    return p.replace(f"data/test_targets/external/{target}", ".") or "."


def static_rows(target: str) -> list[tuple]:
    rows = []
    for f in json.loads((ROOT / f"2026-10-01_{target}/unified_security_report.json").read_text()):
        api = f.get("api") or {}
        loc = f.get("location") or {}
        if api.get("endpoint"):
            point = f"{api.get('method') or ''} {api['endpoint']}".strip()
        elif f["source"] == "CHECKOV" and f.get("resource_id") and target == "sadcloud":
            point = f["resource_id"]
        else:
            line = loc.get("start_line")
            point = short_path(loc.get("file_path"), target) + (f":{line}" if line else "")
        title = f["title"].replace("[Documented API] ", "").replace("[Discovered API] ", "")
        if f["source"] == "SPECTRAL":
            title = (f.get("description") or "").split(": ", 1)[-1]
        rows.append((SOURCE.get(f["source"], f["source"]), f["rule_id"], f["severity"], point, title))
    return rows


def core_rows(target: str) -> list[tuple]:
    rows = []
    data = json.loads((ROOT / f"2026-10-01_{target}/core_findings.json").read_text())["findings"]
    for mod, findings in data.items():
        for f in findings:
            if mod == "bola":
                if not f.get("is_vulnerable"):
                    continue  # prove superate: in dashboard non contano come findings
                rows.append((MODULES[mod], "--", f["severity"], f"{f['method']} {f['endpoint']}",
                             "accesso orizzontale confermato (risposta 200 all'attaccante)"))
            elif mod == "broken_authentication":
                rows.append((MODULES[mod], f["test_id"], f["severita"], "applicazione",
                             f"{f['nome']}: {f['dettagli']}"))
            else:
                line = f.get("line_number")
                point = f.get("endpoint") or (short_path(f.get("file_path"), target) + (f":{line}" if line else ""))
                rows.append((MODULES[mod], f["rule_id"], f["severity"], point, f["category"].replace("_", " ")))
    return rows


def table(rows: list[tuple], caption: str, label: str) -> str:
    out = [r"\begingroup\linespread{1.0}\footnotesize\selectfont\setlength{\tabcolsep}{4pt}",
           r"\begin{longtable}{@{}r >{\raggedright\arraybackslash}p{0.11\linewidth} >{\raggedright\arraybackslash}p{0.2\linewidth} l >{\raggedright\arraybackslash}p{0.25\linewidth} >{\raggedright\arraybackslash}p{0.25\linewidth}@{}}",
           rf"\caption{{{caption}}}\label{{{label}}}\\",
           r"\toprule",
           r"\# & \textbf{Origine} & \textbf{Regola} & \textbf{Sev.} & \textbf{Punto} & \textbf{Descrizione}\\",
           r"\midrule\endfirsthead",
           r"\toprule",
           r"\# & \textbf{Origine} & \textbf{Regola} & \textbf{Sev.} & \textbf{Punto} & \textbf{Descrizione}\\",
           r"\midrule\endhead",
           r"\bottomrule\endfoot"]
    for i, (src, rule, sev, point, desc) in enumerate(rows, 1):
        out.append(f"{i} & {esc(src) if '\\' not in src else src} & {code(rule)} & {SEV.get(sev, esc(sev))} & "
                   f"{code(point)} & {esc(desc)}\\\\")
    out += [r"\end{longtable}", r"\endgroup", ""]
    return "\n".join(out)


parts = [
    "% !TEX root = ../main.tex",
    "% File generato da script/gen_appendice.py a partire da validation/risultati/2026-10-01_<bersaglio>/:",
    "% non modificarlo a mano, rigeneralo.",
    "",
    r"\chapter{Segnalazioni complete sull'insieme di prova}",
    r"\label{app:segnalazioni}",
    "",
    "Questa appendice elenca tutte le segnalazioni che il cruscotto mostra per i bersagli",
    "dell'insieme di prova nella campagna del 1° ottobre 2026, di cui il",
    r"Capitolo~\ref{cap:risultati} riporta i conteggi. Per ciascuna si indicano l'origine",
    "(scanner statico o modulo), la regola, la severità, il punto segnalato (endpoint, file o",
    "risorsa) e una descrizione sintetica. Per la BOLA dinamica si riportano solo le prove che",
    "hanno confermato un accesso non autorizzato; le prove superate sono visibili nel cruscotto",
    "ma non contano come segnalazioni. La modalità sicura di VAmPI non ha una tabella propria:",
    "le segnalazioni coincidono con quelle della modalità vulnerabile, tranne la BOLA dinamica,",
    "che non conferma alcun accesso.",
    "",
]
for target, name in TARGETS:
    s, c = static_rows(target), core_rows(target)
    parts.append(rf"\section*{{{name}}}")
    parts.append(f"La scansione statica produce {len(s)} voci e i moduli Core {len(c)} segnalazioni.")
    parts.append("")
    parts.append(table(s + c, f"Segnalazioni su {name}", f"tab:app-{target}"))
    print(target, "statiche", len(s), "core", len(c))

OUT.write_text("\n".join(parts), encoding="utf-8")
print("scritto", OUT)
