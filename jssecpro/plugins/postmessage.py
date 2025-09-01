
import re
from ..core import Finding
class PostMessage:
    name="postmessage"
    RX_SEND = re.compile(r"\.postMessage\s*\(", re.IGNORECASE)
    RX_RECV = re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.IGNORECASE)
    @classmethod
    def run(cls, files, csp, config):
        out=[]
        for tf in files:
            if tf.kind!="js": continue
            if cls.RX_SEND.search(tf.content or ""):
                out.append(Finding(plugin=cls.name, severity="LOW", message="postMessage sender detected; ensure strict targetOrigin", location=tf.source))
            for m in cls.RX_RECV.finditer(tf.content or ""):
                line = (tf.content[:m.start()]).count("\\n")+1
                out.append(Finding(plugin=cls.name, severity="MEDIUM", message="message event handler; validate event.origin", location=tf.source, line=line))
        return out
