
import re
from ..core import Finding
class SW_WASM:
    name="sw_wasm"
    RX_SW = re.compile(r"navigator\.serviceWorker\.register\s*\(", re.IGNORECASE)
    RX_WASM = re.compile(r"WebAssembly\.(instantiate|compile|instantiateStreaming)", re.IGNORECASE)
    @classmethod
    def run(cls, files, csp, config):
        out=[]
        for tf in files:
            if tf.kind!="js": continue
            if cls.RX_SW.search(tf.content or ""):
                out.append(Finding(plugin=cls.name, severity="INFO", message="Service Worker registration found", location=tf.source))
            for m in cls.RX_WASM.finditer(tf.content or ""):
                line = (tf.content[:m.start()]).count("\\n")+1
                out.append(Finding(plugin=cls.name, severity="LOW", message="WebAssembly usage found", location=tf.source, line=line))
        return out
