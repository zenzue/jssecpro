
import re
from ..core import Finding
class DomSinks:
    name="domsinks"
    RX = re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|\.srcdoc\s*=|\.on\w+\s*=", re.IGNORECASE)
    @classmethod
    def run(cls, files, csp, config):
        out = []
        for tf in files:
            if tf.kind!="js": continue
            for m in cls.RX.finditer(tf.content or ""):
                line = (tf.content[:m.start()]).count("\n")+1
                out.append(Finding(plugin=cls.name, severity="MEDIUM", message="Potential DOM XSS sink", location=tf.source, line=line))
        return out
