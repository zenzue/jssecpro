
import re
from ..core import Finding
class PrototypePollution:
    name="proto"
    RX = re.compile(r"\[\s*['\"]__proto__['\"]\s*\]|\[\s*['\"]prototype['\"]\s*\]|Object\.assign\s*\(\s*.*__proto__", re.IGNORECASE)
    @classmethod
    def run(cls, files, csp, config):
        out=[]
        for tf in files:
            if tf.kind!="js": continue
            for m in cls.RX.finditer(tf.content or ""):
                line = (tf.content[:m.start()]).count("\n")+1
                out.append(Finding(plugin=cls.name, severity="HIGH", message="Prototype pollution indicator", location=tf.source, line=line))
        return out
