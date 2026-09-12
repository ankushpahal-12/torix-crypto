import os
import re

docs_dir = 'docs'

def fix_content(filename, content):
    # 1. Replace invalid KaTeX symbols
    content = content.replace(r'\lll', r'\ll')
    content = content.replace(r'\ggg', r'\gg')
    content = content.replace(r'\mathbin{\Vert}', r'\parallel')
    content = content.replace(r'\mathbin{\parallel}', r'\parallel')
    content = content.replace(r'$\blacksquare$', r'Q.E.D.')
    content = content.replace(r'\blacksquare', r'\text{Q.E.D.}')
    
    # 2. Bitwise operators in math
    content = content.replace(r'\ & \ ', r'\wedge ')
    content = content.replace(r'\ \&\ ', r'\wedge ')
    content = content.replace(r'\ \& ', r'\wedge ')
    content = content.replace(r'\ & ', r'\wedge ')
    content = content.replace(r' \mid ', r' \vee ')
    
    # 3. Big parens
    content = content.replace(r'\Big(', '(').replace(r'\Big)', ')')
    content = content.replace(r'\big(', '(').replace(r'\big)', ')')
    content = content.replace(r'\Big|', '|').replace(r'\big|', '|')
    content = content.replace(r'\Big\{', r'\{').replace(r'\Big\}', r'\}')
    content = content.replace(r'\big\{', r'\{').replace(r'\big\}', r'\}')

    # 4. Clean table cells in Chapter 4
    if 'CHAPTER_4' in filename:
        content = re.sub(
            r'\| \*\*Family A\*\* \| \$0\$ \| \$\(1, 2, 3, 5\)\$ \| Disabled \| Cyclic ShiftRows \(\$\\pi_\{text\{shift\}\}\$\) \|',
            r'| **Family A** | 0 | (1, 2, 3, 5) | Disabled | Cyclic ShiftRows (pi_shift) |',
            content
        )
        content = re.sub(
            r'\| \*\*Family B\*\* \| \$1\$ \| \$\(3, 5, 1, 7\)\$ \| \*\*Active\*\* \| Matrix Transposition \(\$\\pi_\{text\{trans\}\}\$\) \|',
            r'| **Family B** | 1 | (3, 5, 1, 7) | **Active** | Matrix Transposition (pi_trans) |',
            content
        )
        content = re.sub(
            r'\| \*\*Family C\*\* \| \$2\$ \| \$\(5, 1, 7, 3\)\$ \| Disabled \| ShiftRows \+ Transposition \(\$\\pi_\{text\{trans\}\} \\circ \\pi_\{text\{shift\}\}\$\) \|',
            r'| **Family C** | 2 | (5, 1, 7, 3) | Disabled | ShiftRows + Transposition (pi_trans o pi_shift) |',
            content
        )
        content = re.sub(
            r'\| \*\*Family D\*\* \| \$3\$ \| \$\(7, 3, 5, 1\)\$ \| \*\*Active\*\* \| ShiftRows \+ Row-Reverse \(\$\\pi_\{text\{rev\}\} \\circ \\pi_\{text\{shift\}\}\$\) \|',
            r'| **Family D** | 3 | (7, 3, 5, 1) | **Active** | ShiftRows + Row-Reverse (pi_rev o pi_shift) |',
            content
        )
        content = re.sub(
            r'\| Macrocycle Family \| Round Index \$i \\bmod 4\$ \| Von Neumann Rotations \(\$\\alpha, \\beta, \\gamma, \\delta\$\) \| Quadrant Swap \$\\pi_\{text\{quad\}\}\$ \|',
            r'| Macrocycle Family | Round Index (i mod 4) | Von Neumann Rotations (alpha, beta, gamma, delta) | Quadrant Swap pi_quad |',
            content
        )

    # 5. Clean table cells in AEAD & Sponge
    if 'AEAD_AND_SPONGE' in filename:
        content = content.replace(r'$2^{384}$', '2^384')
        content = content.replace(r'**$2^{192}$ (NIST PQ Category 5)**', '**2^192 (NIST PQ Category 5)**')
        content = content.replace(r'$2^{256}$', '2^256')
        content = content.replace(r'**$2^{128}$ (NIST PQ Category 1)**', '**2^128 (NIST PQ Category 1)**')

    # 6. Format all $$ display math blocks properly with isolated lines
    def fix_display_math(match):
        inner = match.group(1).strip()
        # Clean any remaining invalid chars inside math
        inner = inner.replace(r'\lll', r'\ll')
        inner = inner.replace(r'\ & \ ', r'\wedge ')
        inner = inner.replace(r'\ & ', r'\wedge ')
        return f'\n\n$$\n{inner}\n$$\n\n'

    content = re.sub(r'\n*\$\$(.*?)\$\$\n*', fix_display_math, content, flags=re.DOTALL)

    # 7. Collapse excessive blank lines
    content = re.sub(r'\n{3,}', '\n\n', content)

    return content

for f in sorted(os.listdir(docs_dir)):
    if f.endswith('.md'):
        path = os.path.join(docs_dir, f)
        with open(path, 'r', encoding='utf-8') as fp:
            orig = fp.read()
        fixed = fix_content(f, orig)
        with open(path, 'w', encoding='utf-8') as fp:
            fp.write(fixed)
        print(f'Processed {f}')
