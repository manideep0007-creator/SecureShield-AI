import cv2
import numpy as np
img = np.zeros((100, 400, 3), dtype=np.uint8)
cv2.putText(img, 'urgent act now', (10, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
cv2.imwrite('test_image.png', img)
