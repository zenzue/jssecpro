import re
from ..core import Finding

class FrameworkSinks:
    """
    Detect risky framework-specific patterns that commonly lead to XSS or injection:
      - React: dangerouslySetInnerHTML, createElement with HTML string
      - Vue: v-html, dynamic :src/:href (potential scheme injection)
      - Angular: [innerHTML], DomSanitizer bypassSecurityTrust*
      - Svelte: {@html ...} raw HTML directive
      - Next.js: inherits React usage; SSR raw HTML heuristics
    """
    name = "framework"

    EXT_ALLOW = (".js", ".mjs", ".cjs", ".jsx", ".tsx", ".html", ".htm", ".svelte", ".vue")

    RULES = [
        ("React dangerouslySetInnerHTML (object form)", r"dangerouslySetInnerHTML\s*:\s*\{", "HIGH"),
        ("React dangerouslySetInnerHTML (JSX prop)", r"<[^>]+\s+dangerouslySetInnerHTML\s*=\s*\{", "HIGH"),
        ("React createElement with HTML literal", r"React\.createElement\s*\([^,]+,\s*[^)]*['\"].*<[^>]+>.*['\"]\s*\)", "MEDIUM"),

        ("Vue v-html directive", r"v-html\s*=", "HIGH"),
        ("Vue dynamic :src/:href binding", r"(?:\s|:)(?:src|href)\s*=\s*[\":]{1}", "MEDIUM"),

        ("Angular [innerHTML] binding", r"\[innerHTML\]\s*=", "HIGH"),
        ("Angular DomSanitizer bypass", r"\b(bypassSecurityTrust(?:Html|Style|Script|Url|ResourceUrl))\s*\(", "HIGH"),

        ("Svelte {@html ...} directive", r"\{@html\s+[^}]+\}", "HIGH"),

        ("Next.js SSR raw HTML in getServerSideProps/getStaticProps", r"(getServerSideProps|getStaticProps)\s*\([^)]*\)\s*\{[^}]*<[^>]+>[^}]*\}", "MEDIUM"),
    ]

    DANGER_HINTS = [
        (r"<\s*\w+", 1),
        (r"\b(html|raw|unsafe|inner|markup|template)\b", 1),
        (r"javascript\s*:", 2),
        (r"data\s*:", 1),
    ]

    @classmethod
    def _looks_extra_dangerous(cls, snippet: str) -> int:
        """
        Return a bump score [0..2] based on dangerous hints in the snippet.
        """
        if not snippet:
            return 0
        score = 0
        lower = snippet.lower()
        for rx, bump in cls.DANGER_HINTS:
            if re.search(rx, lower):
                score = max(score, bump)
        return score

    @staticmethod
    def _bump_severity(base: str, bump: int) -> str:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        idx = max(0, order.index(base) if base in order else 2)
        return order[min(len(order) - 1, idx + bump)]

    @classmethod
    def run(cls, files, csp, config):
        out = []
        ignores = set()
        try:
            raw_ignores = (config or {}).get("framework_ignores", []) if isinstance(config, dict) else []
            for pat in raw_ignores:
                ignores.add(re.compile(pat, re.IGNORECASE))
        except Exception:
            pass

        for tf in files:
            if not tf.source.lower().endswith(clsEXT := cls.EXT_ALLOW):
                if tf.kind != "js":
                    continue

            content = tf.content or ""
            if any(rx.search(tf.source) for rx in ignores):
                continue

            for label, rx, base_sev in cls.RULES:
                reg = re.compile(rx, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                for m in reg.finditer(content):
                    line = (content[:m.start()]).count("\n") + 1
                    start = max(0, m.start() - 80)
                    end = min(len(content), m.end() + 80)
                    snippet = content[start:end]

                    bump = cls._looks_extra_dangerous(snippet)
                    sev = cls._bump_severity(base_sev, bump)

                    hint = None
                    if "dangerouslySetInnerHTML" in label or "v-html" in label or "[innerHTML]" in label or "Svelte" in label:
                        hint = (
                            "Sanitize/encode untrusted content before rendering. "
                            "Prefer safe templating; for React use sanitized strings or libraries like DOMPurify "
                            "with strict policies; for Angular use the default sanitization and avoid bypass* methods; "
                            "for Svelte/Vue avoid raw HTML unless strictly sanitized."
                        )
                    elif "createElement" in label:
                        hint = "Avoid passing raw HTML strings as children; render as text or sanitize first."
                    elif "DomSanitizer bypass" in label:
                        hint = "Avoid bypassSecurityTrust* unless absolutely necessary and after strict sanitization."
                    elif "dynamic :src/:href" in label:
                        hint = "Validate URL schemes; block javascript:, data: unless explicitly intended."

                    out.append(Finding(
                        plugin=cls.name,
                        severity=sev,
                        message=f"{label} usage",
                        location=tf.source,
                        line=line,
                        extra={
                            "extract": snippet.strip()[:300],
                            "base_severity": base_sev,
                            "bump_from_indicators": bump,
                            "hint": hint
                        }
                    ))
        return out
