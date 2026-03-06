from dataclasses import dataclass


@dataclass
class Finding:
    name: str
    severity: str
    description: str
    recommendation: str