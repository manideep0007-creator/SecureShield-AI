import pymupdf
import os

pdf_path = "SecureShield_AI_System_Architecture.pdf"
doc = pymupdf.open(pdf_path)
scratch_dir = r"C:\Users\N.Manideep\.gemini\antigravity-ide\brain\ca3d09dd-23c1-496a-8682-14d36d409f2f\scratch"

for p in range(len(doc)):
    pix = doc[p].get_pixmap(dpi=150)
    img_path = os.path.join(scratch_dir, f"arch_page_{p + 1}.png")
    pix.save(img_path)

print(f"Rendered all {len(doc)} pages to {scratch_dir}")
doc.close()
