
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
import os, requests
from bs4 import BeautifulSoup

@dataclass
class TargetFile:
    source: str            # path or URL
    content: str
    kind: str              # 'js'|'html'
    meta: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Finding:
    plugin: str
    severity: str          # INFO|LOW|MEDIUM|HIGH|CRITICAL
    message: str
    location: str
    line: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)

class Collector:
    def __init__(self, path: Optional[str]=None, url: Optional[str]=None, timeout:int=10):
        self.path = path
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent":"jssecpro/1.1"})
        self.csp_headers: Dict[str,str] = {}

    def collect(self) -> List[TargetFile]:
        if self.path:
            return self._collect_path(self.path)
        elif self.url:
            return self._collect_url(self.url)
        else:
            raise ValueError("Provide --path or --url")

    def _collect_path(self, root: str) -> List[TargetFile]:
        items: List[TargetFile] = []
        for dp,_,files in os.walk(root):
            for fn in files:
                full = os.path.join(dp, fn)
                low = fn.lower()
                if not (low.endswith((".js",".mjs",".cjs",".html",".htm"))):
                    continue
                try:
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                kind = "html" if low.endswith((".html",".htm")) else "js"
                items.append(TargetFile(source=full, content=content, kind=kind))
        return items

    def _collect_url(self, url: str) -> List[TargetFile]:
        items: List[TargetFile] = []
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            csp = r.headers.get("Content-Security-Policy")
            if csp: self.csp_headers[r.url] = csp
            html = r.text or ""
        except Exception:
            return items
        if html:
            items.append(TargetFile(source=url, content=html, kind="html"))
            soup = BeautifulSoup(html, "html.parser")
            for s in soup.find_all("script"):
                src = s.get("src")
                if not src:
                    items.append(TargetFile(source=f"{url}#inline", content=s.text or "", kind="js"))
                    continue
                import urllib.parse
                full = urllib.parse.urljoin(url, src)
                try:
                    rs = self.session.get(full, timeout=self.timeout)
                    items.append(TargetFile(source=full, content=rs.text or "", kind="js",
                                            meta={"integrity": s.get("integrity"), "crossorigin": s.get("crossorigin")}))
                except Exception:
                    pass
        return items
