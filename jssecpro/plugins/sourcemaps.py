
import re
from ..core import Finding
class SourceMaps:
    name="sourcemaps"
    RX = re.compile(r"//#\s*sourceMappingURL\s*=\s*(.+)$", re.MULTILINE)
    @classmethod
    def run(cls, files, csp, config):
        out=[]
        for tf in files:
            if tf.kind!="js": continue
            for m in cls.RX.finditer(tf.content or ""):
                line = (tf.content[:m.start()]).count("\\n")+1
                out.append(Finding(plugin=cls.name, severity="LOW", message="Source map reference exposed", location=tf.source, line=line))
        return out
