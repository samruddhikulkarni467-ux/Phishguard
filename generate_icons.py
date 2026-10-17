from PIL import Image, ImageDraw

def create_icon(size):
    # Create a simple icon with a red warning symbol on a green background
    img = Image.new('RGBA', (size, size), color=(7, 94, 84, 255)) # WhatsApp Green
    draw = ImageDraw.Draw(img)
    
    # Draw a warning triangle
    margin = size // 5
    p1 = (size // 2, margin)
    p2 = (margin, size - margin)
    p3 = (size - margin, size - margin)
    draw.polygon([p1, p2, p3], fill=(255, 0, 0, 255)) # Red Triangle
    
    # Draw an exclamation mark inside the triangle
    draw.text((size // 2 - size // 15, size // 2), "!", fill=(255, 255, 255, 255))
    
    img.save(f'/home/ubuntu/whatsapp_fraud_detector/icons/icon{size}.png')

for size in [16, 48, 128]:
    create_icon(size)
