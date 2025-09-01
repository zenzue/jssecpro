
import re
from ..core import Finding
class FrameworkSinks:
    name="framework"
    RULES = [
        ("React dangerouslySetInnerHTML", r"dangerouslySetInnerHTML\s*:\s*\{", "HIGH"),
        ("Vue v-html", r"v-html\s*=", "HIGH"),
        ("Angular [innerHTML]", r"\[innerHTML\]\s*=", "HIGH"),
    ]
    @classmethod
    def run(cls, files, csp, config):
        out=[]
        for tf in files:
            if tf.kind!="js" and not tf.source.lower().endswith((".html",".htm")): continue
            for label, rx, sev in cls.RULES:
                rg = re.compile(rx, re.IGNORECASE)
                for m in rg.finditer(tf.content or ""):
                    line = (tf.content[:m.start()]).count("\n")+1
                    out.append(Finding(plugin=cls.name, severity=sev, message=f"{label} usage", location=tf.source, line=line))
        return out
