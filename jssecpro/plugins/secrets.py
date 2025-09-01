
import re
from ..core import Finding

RULES = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "HIGH"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    ("Slack Token", r"(xox[baprs]-[0-9A-Za-z-]+)", "HIGH"),
    ("Private RSA Key", r"-----BEGIN( RSA)? PRIVATE KEY-----", "CRITICAL"),
]

class SecretScanner:
    name = "secrets"
    @classmethod
    def run(cls, files, csp, config):
        findings = []
        for tf in files:
            for label, rx, sev in RULES:
                reg = re.compile(rx)
                for m in reg.finditer(tf.content or ""):
                    line = (tf.content[:m.start()]).count("\n")+1
                    findings.append(Finding(plugin=cls.name, severity=sev, message=f"{label} found", location=tf.source, line=line))
        return findings
