"""Exploit ranking algorithm and grouping logic.

Ranks exploits by a composite score based on source quality, GitHub stars,
LLM classification, and verification status.  Groups them into display
categories for the ``info`` command.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from eip_search.models import Exploit

# ---------------------------------------------------------------------------
# Metasploit exploit_rank → base score
# ---------------------------------------------------------------------------
_MSF_RANK_SCORES: dict[str | None, float] = {
    "excellent": 1000,
    "great": 900,
    "good": 800,
    "normal": 700,
    "manual": 650,
    "low": 500,
    "average": 700,
}
_MSF_DEFAULT = 600  # Metasploit module with unknown/null rank

# ---------------------------------------------------------------------------
# LLM classification modifier
# ---------------------------------------------------------------------------
_LLM_MODIFIERS: dict[str | None, float] = {
    "working_poc": 100,
    "exploit": 100,
    "scanner": 50,
    "tool": 25,
    "writeup": -50,
    "stub": -100,
    "trojan": -9999,
    "suspicious": -5000,
}


def rank_exploit(exploit: Exploit) -> float:
    """Compute a numeric ranking score for an exploit.

    Higher is better.  Trojans/suspicious get deeply negative scores.
    """
    source = exploit.source
    stars = exploit.github_stars or 0
    rank = exploit.exploit_rank
    llm = exploit.llm_classification
    verified = exploit.verified

    # --- Source tier base score ---
    if source == "metasploit":
        base = _MSF_RANK_SCORES.get(rank, _MSF_DEFAULT)
    elif source == "exploitdb":
        base = 500.0 if verified else 300.0
    elif source == "nomisec":
        base = math.log10(stars + 1) * 100 + 100
    elif source == "github":
        base = math.log10(stars + 1) * 100 + 50
    else:
        # trickest, ghsa, writeup, unknown
        base = 10.0

    # --- LLM classification modifier ---
    llm_mod = _LLM_MODIFIERS.get(llm, 0.0)

    # --- Code availability bonus ---
    code_bonus = 25.0 if exploit.has_code else 0.0

    # --- Verified bonus (any source) ---
    verified_bonus = 50.0 if verified else 0.0

    return base + llm_mod + code_bonus + verified_bonus


def rank_exploits(exploits: list[Exploit]) -> list[Exploit]:
    """Rank a list of exploits in-place and return sorted (best first)."""
    for e in exploits:
        e.rank_score = rank_exploit(e)
    return sorted(exploits, key=lambda e: e.rank_score, reverse=True)


# ---------------------------------------------------------------------------
# Grouping for the ``info`` display
# ---------------------------------------------------------------------------

@dataclass
class ExploitGroups:
    """Exploits grouped into display categories."""

    modules: list[Exploit] = field(default_factory=list)       # metasploit
    verified: list[Exploit] = field(default_factory=list)      # exploitdb verified
    pocs: list[Exploit] = field(default_factory=list)          # github, nomisec, exploitdb unverified
    suspicious: list[Exploit] = field(default_factory=list)    # trojan/suspicious
    trickest_count: int = 0                                     # hidden by default
    other_hidden: int = 0                                       # remaining low-quality

    @property
    def visible_count(self) -> int:
        return len(self.modules) + len(self.verified) + len(self.pocs) + len(self.suspicious)

    @property
    def total_count(self) -> int:
        return self.visible_count + self.trickest_count + self.other_hidden


def group_exploits(
    exploits: list[Exploit],
    *,
    show_all: bool = False,
    poc_limit: int = 10,
) -> ExploitGroups:
    """Group and rank exploits into display categories.

    By default, trickest entries are counted but hidden, and PoCs are
    capped at *poc_limit*.  Pass ``show_all=True`` to include everything.
    """
    groups = ExploitGroups()

    # First: separate suspicious and trickest
    remaining: list[Exploit] = []
    for e in exploits:
        if e.is_suspicious:
            groups.suspicious.append(e)
        elif e.source == "trickest" and not show_all:
            groups.trickest_count += 1
        else:
            remaining.append(e)

    # Rank the non-suspicious, non-trickest exploits
    ranked = rank_exploits(remaining)

    # Distribute into groups
    poc_candidates: list[Exploit] = []
    for e in ranked:
        if e.source == "metasploit":
            groups.modules.append(e)
        elif e.source == "exploitdb" and e.verified:
            groups.verified.append(e)
        elif e.source == "trickest":
            # show_all=True case: trickest still goes into pocs
            poc_candidates.append(e)
        else:
            poc_candidates.append(e)

    # Cap PoCs unless show_all
    if show_all or len(poc_candidates) <= poc_limit:
        groups.pocs = poc_candidates
    else:
        groups.pocs = poc_candidates[:poc_limit]
        groups.other_hidden = len(poc_candidates) - poc_limit

    # Rank suspicious too (for consistent ordering)
    rank_exploits(groups.suspicious)
    rank_exploits(groups.modules)
    rank_exploits(groups.verified)

    return groups
