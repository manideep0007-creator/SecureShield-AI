import cv2
import numpy as np

def detect_visual_login_forms(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (5,5), 0)
    edges = cv2.Canny(blur, 50, 150)
    
    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    
    input_fields = 0
    for cnt in contours:
        approx = cv2.approxPolyDP(cnt, 0.02*cv2.arcLength(cnt, True), True)
        if len(approx) == 4:
            x, y, w, h = cv2.boundingRect(approx)
            aspect_ratio = float(w)/h
            # Typical input field width is larger than height (e.g., 3:1 to 20:1)
            # Area should be reasonable enough
            if aspect_ratio >= 2.0 and aspect_ratio <= 20.0 and w > 40 and h > 10:
                input_fields += 1
                
    return input_fields

img = np.zeros((400, 400, 3), dtype=np.uint8)
cv2.rectangle(img, (50, 100), (350, 140), (255, 255, 255), 2)
cv2.rectangle(img, (50, 200), (350, 240), (255, 255, 255), 2)

print(f'Input fields detected: {detect_visual_login_forms(img)}')
