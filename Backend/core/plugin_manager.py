from pathlib import Path
import importlib

BASE_DIR = Path(__file__).resolve().parent.parent
SCANNERS_DIR = BASE_DIR / "scanners"


def load_scanners(context):

    scanners = []

    for file in SCANNERS_DIR.glob("*.py"):

        if file.name in ("__init__.py", "base_scanner.py"):
            continue

        module_name = file.stem

        module = importlib.import_module(
            f"scanners.{module_name}"
        )

        scanners.append(module.Scanner(context))

    return scanners