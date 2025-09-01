
import argparse, os, sys
from rich.console import Console
from .core import Collector
from .reporters import write_json, write_md, write_html
from .plugins.secrets import SecretScanner
from .plugins.danger import DangerousApi
from .plugins.domsinks import DomSinks
from .plugins.framework import FrameworkSinks
from .plugins.proto import PrototypePollution
from .plugins.postmessage import PostMessage
from .plugins.csp import CSP
from .plugins.sri import SRI
from .plugins.sourcemaps import SourceMaps
from .plugins.sw_wasm import SW_WASM
from .plugins.deps import Deps

PLUGINS = {
    "secrets": SecretScanner,
    "danger": DangerousApi,
    "domsinks": DomSinks,
    "framework": FrameworkSinks,
    "proto": PrototypePollution,
    "postmessage": PostMessage,
    "csp": CSP,
    "sri": SRI,
    "sourcemaps": SourceMaps,
    "sw_wasm": SW_WASM,
    "deps": Deps,
}

def main():
    c = Console()
    p = argparse.ArgumentParser(prog="jssecpro", description="JS Security Analysis (plugin-based)")
    sub = p.add_subparsers(dest="cmd")
    scan = sub.add_parser("scan", help="Scan a directory or URL")
    scan.add_argument("--path", help="Directory path to scan")
    scan.add_argument("--url", help="URL to fetch (HTML and linked JS)")
    scan.add_argument("--plugins", help="Comma-list of plugins", default=",".join(PLUGINS.keys()))
    scan.add_argument("--out", default="./reports", help="Output directory")
    scan.add_argument("--html", action="store_true", help="Also write HTML report")

    args = p.parse_args()
    if args.cmd != "scan":
        p.print_help(); sys.exit(1)
    if not args.path and not args.url:
        c.print("[red]Provide --path or --url[/red]"); sys.exit(2)

    selected = [x.strip() for x in (args.plugins or "").split(",") if x.strip()]
    unknown = [x for x in selected if x not in PLUGINS]
    if unknown:
        c.print(f"[red]Unknown plugins: {', '.join(unknown)}[/red]"); sys.exit(3)

    col = Collector(path=args.path, url=args.url)
    files = col.collect()
    c.print(f"Collected [cyan]{len(files)}[/cyan] assets")

    plug_objs = [PLUGINS[k] for k in selected]
    c.print("Running plugins: " + ", ".join([p.name for p in plug_objs]))
    findings = []
    for plug in plug_objs:
        try:
            findings.extend(plug.run(files, col.csp_headers, {}))
        except Exception as e:
            from .core import Finding
            findings.append(Finding(plugin=plug.name, severity="INFO", message=f"Plugin error: {e}", location="(framework)"))

    outdir = os.path.abspath(args.out); os.makedirs(outdir, exist_ok=True)
    write_json(findings, outdir); write_md(findings, outdir)
    if args.html: write_html(findings, outdir)
    c.print(f"[green]Reports written to[/green] {outdir}")
