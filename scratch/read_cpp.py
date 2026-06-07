import os

path_h = r"C:\Users\zortn\.gemini\antigravity-cli\brain\21688d5b-bdfe-404d-98e7-cb450e275bac\.system_generated\steps\520\content.md"
path_cpp = r"C:\Users\zortn\.gemini\antigravity-cli\brain\21688d5b-bdfe-404d-98e7-cb450e275bac\.system_generated\steps\496\content.md"

def search_file(path, name):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if "12" in line or "0x0C" in line or "0x0c" in line or "TYPE_" in line:
            if "TYPE_" in line or "12" in line or "0x0C" in line:
                print(f"{name}:{i}: {line}")

search_file(path_h, "H")
print("----------------")
search_file(path_cpp, "CPP")
