+++
title = "katex bug"
+++

> Display exceptions, such as inconsistent trailing commas and local restrictions, being pushed to one line, or not being displayed

```markdown
$$\begin{cases} f(x) \equiv V_1(x)^2 \pmod{U_1(x)} \\ f(x) \equiv V_2(x)^2 \pmod{U_2(x)} \\ f(x) \equiv V_3(x)^2 \pmod{U_3(x)} \end{cases}$$
```

$$\begin{cases} f(x) \equiv V_1(x)^2 \pmod{U_1(x)} \\ f(x) \equiv V_2(x)^2 \pmod{U_2(x)} \\ f(x) \equiv V_3(x)^2 \pmod{U_3(x)} \end{cases}$$

---

```markdown
$(\text{order\_candidate} / p_i) \cdot G$
```

$(\text{order\_candidate} / p_i) \cdot G$

---

```markdown
$$\text{order\_candidate} \leftarrow \frac{\text{order\_candidate}}{p_i}$$
```

$$\text{order\_candidate} \leftarrow \frac{\text{order\_candidate}}{p_i}$$

---

```markdown
$$
\text{flag\_chocolate}= (a^m+b^m)\bmod p ,
$$
```

$$
\text{flag\_chocolate}= (a^m+b^m)\bmod p ,
$$

---

```markdown
$$
q = p_{\text{crypto}}-1\; / \; 2 = 85\,414\,812\,699\,185\,126\,250\,990\,381\,881\,994\,204\,791 .
$$
```

$$
q = p_{\text{crypto}}-1\; / \; 2 = 85\,414\,812\,699\,185\,126\,250\,990\,381\,881\,994\,204\,791 .
$$

---

```markdown
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
$$
S=S_{0}+\sum_{i,k}b_{i,k}\,d_{i,k} - K\,M,
$$
```

$$
S=S_{0}+\sum_{i,k}b_{i,k}\,d_{i,k} - K\,M,
$$

---

```markdown
   $$
   \text{idek\{ \ldots \}} .
   $$
```

   $$
   \text{idek\{ \ldots \}} .
   $$

---

```markdown
$$
m_{\text{min}} = \underbrace{0x20\cdots20}_{20\text{ 个空格}} 
\qquad
m_{\text{max}} = \underbrace{0x7E\cdots7E}_{20\text{ 个波浪号}} 
$$
```

$$
m_{\text{min}} = \underbrace{0x20\cdots20}_{20\text{ 个空格}} 
\qquad
m_{\text{max}} = \underbrace{0x7E\cdots7E}_{20\text{ 个波浪号}} 
$$


