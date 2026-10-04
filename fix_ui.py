import re
with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

replacements = {
    '#00f0ff': 'var(--accent-secondary)',
    '#39ff14': 'var(--success)',
    '#ff003c': 'var(--danger)',
    '#8ab4f8': 'var(--text-secondary)',
    "'Orbitron'": 'system-ui',
    "Orbitron": 'system-ui',
    "'Rajdhani'": 'system-ui',
    "Rajdhani": 'system-ui',
    "'Fira Code'": 'monospace',
    "Fira Code": 'monospace',
    'rgba(255,0,60,0.1)': 'var(--danger-bg)',
    'rgba(57,255,20,0.1)': 'var(--success-bg)',
    'rgba(255,0,60,0.5)': 'rgba(255, 59, 48, 0.3)',
    'rgba(57,255,20,0.5)': 'rgba(52, 199, 89, 0.3)'
}

for k, v in replacements.items():
    content = content.replace(k, v)

# Update altair chart colors
content = content.replace("alt.value('var(--danger)')", "alt.value('#ff3b30')")
content = content.replace("alt.value('var(--accent-secondary)')", "alt.value('#5ac8fa')")
content = content.replace("labelColor='var(--text-secondary)'", "labelColor='#86868b'")
content = content.replace("titleColor='var(--accent-secondary)'", "titleColor='#5ac8fa'")

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Done!')
