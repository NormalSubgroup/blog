+++
title = "katex bug"

date = "2025-08-10"
description = "Bug trace"

[taxonomies]
tags = ["demo"]
+++

> Display exceptions, such as inconsistent trailing commas and local restrictions, being pushed to one line, or not being displayed

```markdown
{% katex_block() %}
\\begin{cases}
 f(x) \\equiv V_1(x)^2 \\pmod{U_1(x)} \\\\
 f(x) \\equiv V_2(x)^2 \\pmod{U_2(x)} \\\\
 f(x) \\equiv V_3(x)^2 \\pmod{U_3(x)}
 \\end{cases}
{% end %}
```

$$\begin{cases} f(x) \equiv V_1(x)^2 \pmod{U_1(x)} \\ f(x) \equiv V_2(x)^2 \pmod{U_2(x)} \\ f(x) \equiv V_3(x)^2 \pmod{U_3(x)} \end{cases}$$

---

```markdown
{% katex() %}(\\text{order\\_candidate} / p_i) \\cdot G{% end %}
```

$(\text{order\_candidate} / p_i) \cdot G$

---

```markdown
{% katex_block() %}
\\text{order\\_candidate} \\leftarrow \\frac{\\text{order\\_candidate}}{p_i}
{% end %}
```

$$\text{order\_candidate} \leftarrow \frac{\text{order\_candidate}}{p_i}$$

---

```markdown
{% katex_block() %}
\\text{flag\\_chocolate}= (a^m+b^m)\\bmod p ,
{% end %}
```

$$
\text{flag\_chocolate}= (a^m+b^m)\bmod p ,
$$

---

```markdown
{% katex_block() %}
q = p_{\\text{crypto}}-1\\; / \\; 2 = 85\\,414\\,812\\,699\\,185\\,126\\,250\\,990\\,381\\,881\\,994\\,204\\,791 .
{% end %}
```

$$
q = p_{\text{crypto}}-1\; / \; 2 = 85\,414\,812\,699\,185\,126\,250\,990\,381\,881\,994\,204\,791 .
$$

---

```markdown
{% katex_block() %}
B=\\begin{pmatrix}
2 &        &        &        &        & d_{1,6} \\\\
  & 2      &        &        &        & d_{1,7} \\\\
  &        & \\ddots &        &        & \\vdots\\\\n+  &        &        & 2      &        & d_{17,11}\\\\n+  &        &        &        & 1 & -M\\end{pmatrix},
{% end %}
```

$$
B=
\begin{pmatrix}
2 &        &        &        &        & d_{1,6} \\
  & 2      &        &        &        & d_{1,7} \\
  &        & \ddots &        &        & \vdots\\
  &        &        & 2      &        & d_{17,11}\\
  &        &        &        & 1 & -M
\end{pmatrix},
$$

---

```markdown
{% katex_block() %}
S=S_{0}+\\sum_{i,k}b_{i,k}\\,d_{i,k} - K\\,M,
{% end %}
```

$$
S=S_{0}+\sum_{i,k}b_{i,k}\,d_{i,k} - K\,M,
$$

---

```markdown
{% katex_block() %}
\\text{idek\\{ \\ldots \\}} .
{% end %}
```

   $$
   \text{idek\{ \ldots \}} .
   $$

---

```markdown
{% katex_block() %}
m_{\\text{min}} = \\underbrace{0x20\\cdots20}_{20\\text{ 个空格}} \\\\
\\qquad \\\\
m_{\\text{max}} = \\underbrace{0x7E\\cdots7E}_{20\\text{ 个波浪号}}
{% end %}
```

$$
m_{\text{min}} = \underbrace{0x20\cdots20}_{20\text{ 个空格}} 
\qquad
m_{\text{max}} = \underbrace{0x7E\cdots7E}_{20\text{ 个波浪号}} 
$$
