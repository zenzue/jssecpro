
from bs4 import BeautifulSoup
from ..core import Finding
class SRI:
    name="sri"
    @classmethod
    def run(cls, files, csp, config):
        out=[]
        for tf in files:
            if tf.kind!="html": continue
            soup = BeautifulSoup(tf.content or "", "html.parser")
            for s in soup.find_all("script"):
                src = s.get("src")
                if src and (src.startswith("http://") or src.startswith("https://")):
                    if not s.get("integrity"):
                        out.append(Finding(plugin=cls.name, severity="LOW", message="External script without SRI", location=tf.source))
        return out
