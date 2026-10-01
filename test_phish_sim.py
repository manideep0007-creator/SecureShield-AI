import cv2
import easyocr
import numpy as np

reader = easyocr.Reader(['en'], gpu=False)

img = np.zeros((300, 400, 3), dtype=np.uint8)
img[:] = (255, 255, 255)
cv2.putText(img, 'Sign in to your account', (50, 50), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)
cv2.rectangle(img, (50, 100), (350, 140), (0, 0, 0), 2)
cv2.rectangle(img, (50, 160), (350, 200), (0, 0, 0), 2)
cv2.putText(img, 'Password', (50, 155), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)

ocr_results = reader.readtext(img)
ocr_texts = [res[1] for res in ocr_results if res[2] > 0.3]
joined_text = " ".join(ocr_texts).lower()

cred_keywords = ["login", "sign in", "password", "username", "verify account", "enter credentials"]
has_cred_text = any(kw in joined_text for kw in cred_keywords)

gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
blur = cv2.GaussianBlur(gray, (5, 5), 0)
edges = cv2.Canny(blur, 50, 150)
contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

input_field_count = 0
for cnt in contours:
    approx = cv2.approxPolyDP(cnt, 0.02 * cv2.arcLength(cnt, True), True)
    if len(approx) == 4:
        x, y, w, h = cv2.boundingRect(approx)
        if 2.0 <= float(w)/h <= 20.0 and w > 40 and h > 10:
            input_field_count += 1

print(f'has_cred_text: {has_cred_text}')
print(f'input_field_count: {input_field_count}')
