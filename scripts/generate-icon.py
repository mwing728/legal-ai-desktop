"""Generate a 1024x1024 app icon for Legal AI Assistant."""
from PIL import Image, ImageDraw, ImageFont
import math

SIZE = 1024
img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Rounded rectangle background (amber-600 #d97706)
margin = 40
radius = 200
bg_color = (217, 119, 6, 255)
draw.rounded_rectangle(
    [margin, margin, SIZE - margin, SIZE - margin],
    radius=radius,
    fill=bg_color,
)

# Draw a stylized scales-of-justice icon in white
cx, cy = SIZE // 2, SIZE // 2 - 20
white = (255, 255, 255, 255)
stroke_w = 28

# Vertical pillar
draw.rectangle([cx - stroke_w // 2, cy - 200, cx + stroke_w // 2, cy + 260], fill=white)

# Horizontal beam
beam_y = cy - 200
beam_half = 240
draw.rectangle([cx - beam_half, beam_y - stroke_w // 2, cx + beam_half, beam_y + stroke_w // 2], fill=white)

# Left pan (arc + lines)
lx = cx - beam_half
ly = beam_y
pan_drop = 200
pan_w = 120

# Left chain lines
draw.line([(lx, ly), (lx - pan_w, ly + pan_drop)], fill=white, width=stroke_w // 2)
draw.line([(lx, ly), (lx + pan_w, ly + pan_drop)], fill=white, width=stroke_w // 2)
# Left pan dish
draw.arc(
    [lx - pan_w - 10, ly + pan_drop - 30, lx + pan_w + 10, ly + pan_drop + 50],
    start=0, end=180, fill=white, width=stroke_w // 2,
)

# Right pan
rx = cx + beam_half
ry = beam_y
# Right chain lines
draw.line([(rx, ry), (rx - pan_w, ry + pan_drop)], fill=white, width=stroke_w // 2)
draw.line([(rx, ry), (rx + pan_w, ry + pan_drop)], fill=white, width=stroke_w // 2)
# Right pan dish
draw.arc(
    [rx - pan_w - 10, ry + pan_drop - 30, rx + pan_w + 10, ry + pan_drop + 50],
    start=0, end=180, fill=white, width=stroke_w // 2,
)

# Base
base_y = cy + 260
base_half = 140
draw.rounded_rectangle(
    [cx - base_half, base_y, cx + base_half, base_y + stroke_w],
    radius=stroke_w // 2,
    fill=white,
)

# "AI" text at bottom
try:
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 80)
except OSError:
    font = ImageFont.load_default()

text = "AI"
bbox = draw.textbbox((0, 0), text, font=font)
tw = bbox[2] - bbox[0]
th = bbox[3] - bbox[1]
draw.text(
    (cx - tw // 2, base_y + 50),
    text,
    fill=white,
    font=font,
)

img.save("app-icon.png")
print("Generated app-icon.png (1024x1024)")
