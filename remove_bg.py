from PIL import Image

# Process the circle logo (43229)
img1 = Image.open('IMG_20260221_143229.png').convert('RGBA')
data = img1.getdata()

# Get the background color (assume it's the top-left corner)
bg_color = data[0]
print(f"Circle logo background color: {bg_color}")

# Remove background - create new image with transparency
new_data = []
for item in data:
    # If color is similar to background, make transparent
    if item[:3] == bg_color[:3]:  # Compare RGB, ignore alpha
        new_data.append((255, 255, 255, 0))  # Transparent
    else:
        new_data.append(item)

img1.putdata(new_data)
img1.save('icon-circle.png')
print("Saved: icon-circle.png")

# Process the full logo (43233)
img2 = Image.open('IMG_20260221_143233.png').convert('RGBA')
data = img2.getdata()

bg_color = data[0]
print(f"\nFull logo background color: {bg_color}")

new_data = []
for item in data:
    if item[:3] == bg_color[:3]:
        new_data.append((255, 255, 255, 0))
    else:
        new_data.append(item)

img2.putdata(new_data)
img2.save('logo-header.png')
print("Saved: logo-header.png")

print("\nDone! Backgrounds removed.")
