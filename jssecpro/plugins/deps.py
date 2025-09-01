
import os, json
from ..core import Finding
class Deps:
    name="deps"
    @classmethod
    def run(cls, files, csp, config):
        roots=set(); out=[]
        for tf in files:
            if tf.source.startswith("http"): continue
            d=os.path.dirname(tf.source)
            while True:
                pj=os.path.join(d,"package.json")
                if os.path.isfile(pj): roots.add(pj); break
                nd=os.path.dirname(d)
                if nd==d: break
                d=nd
        for pj in roots:
            try:
                data=json.load(open(pj,"r",encoding="utf-8"))
                out.append(Finding(plugin=cls.name, severity="INFO", message="Dependency inventory", location=pj,
                                   extra={"dependencies":data.get("dependencies",{}),"devDependencies":data.get("devDependencies",{})}))
            except Exception: pass
        return out
