from PIL import Image

def encode(image_path, message, output_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())

    # Convert message to binary
    binary = ''.join(format(ord(c), '08b') for c in message)

    # Encode in LSB
    new_pixels = []
    idx = 0
    for pixel in pixels:
        if idx < len(binary):
            r, g, b = pixel
            if idx < len(binary):
                r = (r & ~1) | int(binary[idx])
                idx += 1
            if idx < len(binary):
                g = (g & ~1) | int(binary[idx])
                idx += 1
            if idx < len(binary):
                b = (b & ~1) | int(binary[idx])
                idx += 1
            new_pixels.append((r, g, b))
        else:
            new_pixels.append(pixel)
    
    encoded_img = Image.new(img.mode, img.size)
    encoded_img.putdata(new_pixels)
    encoded_img.save(output_path)
    print(f"Message encoded in {output_path}")

def decode(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())

    # Extract LSB
    binary = ''
    for pixel in pixels:
        r, g, b = pixel
        binary += str(r & 1)
        binary += str(g & 1)
        binary += str(b & 1)

    # Convert binary to text
    message = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if byte == '11111110':  # End marker
            break
        message += chr(int(byte, 2))

    return message

encode('3x3_pattern.png', 'HEY', '3x3_pattern_encoded.png')
print("Decoded:", decode('3x3_pattern_encoded.png'))
