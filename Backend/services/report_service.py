def generate_summary(findings):
    return {
        "total": len(findings),
        "high": sum(1 for f in findings if f["severity"] == "High"),
        "medium": sum(1 for f in findings if f["severity"] == "Medium"),
        "low": sum(1 for f in findings if f["severity"] == "Low"),
    }