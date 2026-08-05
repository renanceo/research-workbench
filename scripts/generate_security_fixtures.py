from __future__ import annotations

from pathlib import Path

from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "fixtures" / "security" / "GATE0-001-missing-font-text-budget.pdf"


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    stream = DecodedStreamObject()
    stream.set_data(b"BT (" + b"x" * 500 + b") Tj ET")
    page[NameObject("/Contents")] = stream
    with OUTPUT.open("wb") as handle:
        writer.write(handle)


if __name__ == "__main__":
    main()

