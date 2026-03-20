from dataclasses import dataclass, asdict


SEVERITY_LEVELS = {"critical", "high", "medium", "low"}


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
