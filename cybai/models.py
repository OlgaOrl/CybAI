from dataclasses import dataclass, field, asdict
from typing import Literal

SEVERITY_LEVELS = {"critical", "high", "medium", "low"}
ANALYSIS_MODES = {"demo", "ai", "fallback"}
CONFIDENCE_LEVELS = {"high", "medium", "low"}


@dataclass
class Risk:
    id: str
    type: str
    title: str
    description: str
    severity: str
    location: str
    found_at: str

    def __post_init__(self):
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity '{self.severity}'. Must be one of: {SEVERITY_LEVELS}"
            )

    def to_dict(self):
        return asdict(self)


@dataclass
class RiskAnalysis:
    risk_id: str
    cvss_score: float
    severity: Literal["high", "medium", "low"]
    why_dangerous_et: str
    recommendation_et: str
    confidence: Literal["high", "medium", "low"]
    eits_mapping: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    analysis_mode: Literal["demo", "ai", "fallback"] = "fallback"

    def __post_init__(self):
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity '{self.severity}'. Must be one of: {SEVERITY_LEVELS}"
            )

        if self.analysis_mode not in ANALYSIS_MODES:
            raise ValueError(
                f"Invalid analysis_mode '{self.analysis_mode}'. "
                f"Must be one of: {ANALYSIS_MODES}"
            )

        if self.confidence not in CONFIDENCE_LEVELS:
            raise ValueError(
                f"Invalid confidence '{self.confidence}'. "
                f"Must be one of: {CONFIDENCE_LEVELS}"
            )

        if not (0.0 <= self.cvss_score <= 10.0):
            raise ValueError("cvss_score must be between 0.0 and 10.0")

        if len(self.why_dangerous_et) > 800:
            raise ValueError("why_dangerous_et too long")

        if len(self.recommendation_et) > 1200:
            raise ValueError("recommendatioin_et too long")

    def to_dict(self):
        return asdict(self)
