
import re
from ..core import Finding
class DangerousApi:
    name="danger"
    RX = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*['\"][^'\"]+['\"]|\bdocument\.write\s*\(|\binnerHTML\s*=", re.IGNORECASE)
    @classmethod
    def run(cls, files, csp, config):
        out = []
        for tf in files:
            if tf.kind != "js": continue
            for m in cls.RX.finditer(tf.content or ""):
                line = (tf.content[:m.start()]).count("\n")+1
                out.append(Finding(plugin=cls.name, severity="MEDIUM", message="Dangerous API usage", location=tf.source, line=line))
        return out
