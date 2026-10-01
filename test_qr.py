import cv2
import numpy as np

encoder = cv2.QRCodeEncoder.create()
qr_img = encoder.encode('https://malicious.com')
qr_img = cv2.resize(qr_img, (0,0), fx=10, fy=10, interpolation=cv2.INTER_NEAREST)
qr_img = cv2.copyMakeBorder(qr_img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=[255])

detector = cv2.QRCodeDetector()
data, bbox, _ = detector.detectAndDecode(qr_img)
print(f'Detected: {data}')
