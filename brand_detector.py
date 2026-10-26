"""Explainable brand impersonation heuristics for untrusted email From headers.

No network/DNS lookups. A matching domain is not authenticated; this module
only spots lookalike strings. Keep reference domains verified and up to date.
"""

import json
from email.utils import parseaddr
from pathlib import Path
import re
import unicodedata

REFERENCES = Path(__file__).with_name('brand_domains.json')

# Frequent Cyrillic/Greek glyphs that resemble Latin letters, for demo only.
# This is NOT a complete Unicode confusables implementation.
CONFUSABLES = str.maketrans({
    'а':'a', 'е':'e', 'о':'o', 'р':'p', 'с':'c', 'х':'x', 'у':'y',
    'і':'i', 'ј':'j', 'к':'k', 'м':'m', 'т':'t', 'н':'h', 'в':'b',
    'Α':'a', 'Β':'b', 'Ε':'e', 'Ζ':'z', 'Η':'h', 'Ι':'i',
    'Κ':'k', 'Μ':'m', 'Ν':'n', 'Ο':'o', 'Ρ':'p', 'Τ':'t', 'Χ':'x',
    'α':'a', 'ο':'o', 'ρ':'p', 'ν':'v', 'ι':'i', 'κ':'k',
})


def canonical_domain(domain: str) -> str:
    """Store domain in lowercase ASCII IDNA form when possible."""
    domain = unicodedata.normalize('NFKC', (domain or '').strip().rstrip('.')).casefold()
    if not domain:
        return ''
    try:
        return domain.encode('idna').decode('ascii')
    except UnicodeError:
        return domain


def visual_domain(domain: str) -> str:
    """Approximate visually confusable hostname text for comparison."""
    labels = []
    for label in canonical_domain(domain).split('.'):
        try:
            decoded = label.encode('ascii').decode('idna') if label.startswith('xn--') else label
        except UnicodeError:
            decoded = label
        labels.append(unicodedata.normalize('NFKC', decoded).casefold().translate(CONFUSABLES))
    return '.'.join(labels)


def is_same_or_subdomain(domain: str, reference: str) -> bool:
    """Label-aware check, not unsafe substring or endswith(reference)."""
    return domain == reference or domain.endswith('.' + reference)


def levenshtein(a: str, b: str) -> int:
    """Small, dependency-free edit distance used only for nearby domains."""
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(current[-1] + 1, previous[j] + 1,
                               previous[j - 1] + (char_a != char_b)))
        previous = current
    return previous[-1]


def detect_brand_spoofing(from_header: str, protected_brands: dict | None = None) -> list[dict]:
    """Return suspicious signals; do not claim that any email is proven malicious."""
    if protected_brands is None:
        protected_brands = json.loads(REFERENCES.read_text(encoding='utf-8'))
    display_name, address = parseaddr(from_header or '')
    if '@' not in address:
        return []
    raw_domain = address.rsplit('@', 1)[1]
    domain = canonical_domain(raw_domain)
    visual = visual_domain(raw_domain)
    findings = []

    for brand, references in protected_brands.items():
        trusted = [canonical_domain(item) for item in references if item]
        trusted = [item for item in trusted if item]
        if not trusted:
            continue
        if any(is_same_or_subdomain(domain, ref) for ref in trusted):
            # A reference-domain match alone cannot prove legitimate origin.
            continue

        trigger = None
        score = 0
        reference = ''
        # Prioritize strongest explanation, rather than adding all overlapping rules.
        for ref in trusted:
            comparison = visual_domain(ref)
            if is_same_or_subdomain(visual, comparison):
                trigger, score, reference = 'Unicode/lookalike characters imitate a reference domain', 65, ref
                break
        if not trigger:
            for ref in trusted:
                if ref in visual:
                    trigger, score, reference = 'Reference domain embedded inside another domain', 60, ref
                    break
        if not trigger:
            for ref in trusted:
                if levenshtein(visual, visual_domain(ref)) <= 2:
                    trigger, score, reference = 'Domain spelling is very similar to a reference domain (typosquatting)', 60, ref
                    break
        if not trigger:
            brand_token = re.sub(r'[^a-z0-9]', '', brand.casefold())
            if brand_token and brand_token in visual.replace('-', ''):
                trigger, score, reference = 'Brand name appears inside a different domain', 40, trusted[0]
        if not trigger and re.search(rf'(?<!\w){re.escape(brand)}(?!\w)', display_name, re.IGNORECASE):
            trigger, score, reference = 'Display name claims the brand but sender domain is not a reference', 35, trusted[0]
        if trigger:
            findings.append({
                'brand': brand,
                'sender_domain': domain,
                'reference': reference,
                'finding': trigger,
                'points': score,
            })
    return findings
