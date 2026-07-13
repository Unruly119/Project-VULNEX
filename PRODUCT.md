# Product

## Register

product

## Users

IT administrators and teachers at Thai educational institutions with limited cybersecurity expertise. They use VULNEX to discover and understand security risks on their websites — not to perform attacks. Primary context: running a scan before a compliance review, a school audit, or after hearing about a breach nearby. They need findings explained in plain Thai, not raw CVE IDs.

## Product Purpose

VULNEX passively scans a target URL across 8 security modules (headers, SSL, HTML/SRI, DNS, cookies, JS exposure, subdomains, server info + CVE lookup), scores the site 0–100, generates a Gemini AI analysis in Thai, and exports a single-page PDF audit report. Success = a non-technical user understands what's wrong, how serious it is, and what to do first.

Four further modules (CORS, CMS, HTTP methods, open files) are written but **suspended**: they send non-passive requests, which would contradict the "Passive Scan Only" promise. Keeping that promise literally true is a product commitment, not just a technical one — re-enabling any of them requires a deliberate decision (see `SECURITY-AUDIT.md`, finding A1).

## Brand Personality

Trusted · Clear · Guiding — expert confidence that doesn't intimidate. The tool should feel like a knowledgeable colleague, not a hacker dashboard or a government portal.

## Anti-references

- Dark-mode neon hacker aesthetic (Shodan, Kali tools) — too intimidating for teacher audiences
- Generic SaaS admin template (cold flat blues, cards everywhere, Tailwind defaults) — soulless, interchangeable
- Dated Thai government portal look (Times New Roman, heavy table grids, no visual hierarchy)

## Design Principles

1. **Show severity, not noise** — critical issues must be immediately visible; passing checks should recede.
2. **Thai-first legibility** — every UI string exists in Thai; English only for proper nouns (CVE IDs, header names, protocol strings). Prompt for Thai glyphs, AnthropicSans for Latin.
3. **Warm authority** — the Fable palette (parchment background, terracotta accent) signals credibility without aggression.
4. **Progressive disclosure** — summary first, detail on demand. The executive score and risk level are the hero; raw scan data is a tab, not the lead.
5. **One action at a time** — scan → review → export. No branching flows, no feature sprawl.

## Accessibility & Inclusion

- Target WCAG 2.1 AA minimum for all text contrast
- Thai + English bilingual; all severity labels in Thai with English codes parenthetical
- `prefers-reduced-motion` already honoured in index.css — maintain on all new animations
- No reliance on color alone for severity (labels + icons back up color)
