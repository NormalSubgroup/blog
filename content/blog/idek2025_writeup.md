+++
title = "idekCTF 2025 Team WriteUp"
date = "2025-08-09"
description = "AK Cryptography!!!"

[taxonomies]
tags = ["idekCTF", "Team", "WriteUp", "Cryptography", "Reverse", "Web"]
+++

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

# sanity

## check

签到

## survey

问卷

# rev

## constructor

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

# --- Run the solver ---
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
            log.success(f"🎉 Success! Flag: {flag}")
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

