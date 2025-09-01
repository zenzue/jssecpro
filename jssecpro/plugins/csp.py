
from ..core import Finding
class CSP:
    name="csp"
    @classmethod
    def run(cls, files, csp_headers, config):
        out=[]
        if not csp_headers:
            out.append(Finding(plugin=cls.name, severity="INFO", message="No CSP captured (URL mode only)", location="(global)"))
            return out
        for origin, csp in csp_headers.items():
            lc = csp.lower()
            sev = "LOW"
            issues = []
            if "script-src" not in lc:
                sev="MEDIUM"; issues.append("missing script-src")
            if "'unsafe-inline'" in lc:
                sev="HIGH"; issues.append("uses 'unsafe-inline'")
            if "trusted-types" not in lc:
                issues.append("no Trusted Types")
            if "nonce-" not in lc and "sha256-" not in lc:
                issues.append("no nonces/hashes")
            if issues:
                out.append(Finding(plugin=cls.name, severity=sev, message="CSP issues: "+", ".join(issues), location=origin))
        return out
