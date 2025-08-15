#utils/estructura.py

"""
    Genera automáticamente el fichero "estructura.txt"
"""

from pathlib import Path

IGNORE = {".git", "__pycache__", ".venv", "venv", "dist", "build", ".pytest_cache"}
ROOT = Path(__file__).resolve().parents[1]

def render(dirpath: Path, prefix: str = "") -> list[str]:
    lines = []
    items = [p for p in sorted(dirpath.iterdir(), key=lambda p: (p.is_file(), p.name.lower())) if p.name not in IGNORE]
    for i, p in enumerate(items):
        elbow = "└─ " if i == len(items)-1 else "├─ "
        cont  = "   " if i == len(items)-1 else "│  "
        if p.is_dir():
            lines.append(f"{prefix}{elbow}{p.name}/")
            lines.extend(render(p, prefix + cont))
        else:
            lines.append(f"{prefix}{elbow}{p.name}")
    return lines

if __name__ == "__main__":
    lines = [f"{ROOT.name}/"] + render(ROOT)
    (ROOT / "estructura.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("estructura.txt actualizado")

