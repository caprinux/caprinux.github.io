from PIL import Image
import numpy as np

# create 3x3 image where pixels are RED GREEN BLUE RED GREEN BLUE RED GREEN BLUE

colors = np.array([[[255, 0, 0], [0, 255, 0], [0, 0, 255]],
                   [[255, 0, 0], [0, 255, 0], [0, 0, 255]],
                   [[255, 0, 0], [0, 255, 0], [0, 0, 255]]], dtype=np.uint8)
img = Image.fromarray(colors)
img.save('looping_rgb.jpg', 'JPEG')

# let's reopen the image to view the values

img = Image.open("looping_rgb.jpg")
pixels = list(img.getdata())
print(pixels)

