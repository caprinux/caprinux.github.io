# coding: utf-8
from PIL import Image

im = Image.open("./srgb_wheel.jpg")
pixels = list(im.getdata())
print("First 10 pixel values:", pixels[:10])
