import pypdf
import sys

# Force output to utf-8
sys.stdout.reconfigure(encoding='utf-8')

reader = pypdf.PdfReader("JETI_Telem_protocol_EN_V1.07.pdf")
pages_to_print = [4, 5, 8]

for page_num in pages_to_print:
    print("=" * 60)
    print(f"PAGE {page_num}")
    print("=" * 60)
    text = reader.pages[page_num - 1].extract_text()
    print(text)
