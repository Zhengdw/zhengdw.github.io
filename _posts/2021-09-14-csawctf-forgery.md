---
title: "[CSAW CTF 2021] forgery"
keywords: ctf, cryptography, crypto, number theory
---

# [CSAW CTF 2021] forgery

## tl;dr

The server asks for one of three strings but must be signed correctly using the
[Digital Signiture Algorithm](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) (DSA)
with prime $$p$$.
Only the lower 1024 bits of input matter so we can fake a message by using number theory and hide the message in higher order bits.

## Description 

crypto/bits; 24 solves, 497 points
Challenge authors: `Robin_Jadoul` and `jack`

Felicity and Cisco would like to hire you as an intern for a new security company that they are forming. They have given you a black box signature verification system to test out and see if you can forge a signature. Forge it and you will get a passphrase to be hired! 

```
nc crypto.chal.csaw.io 5006
```

[forgery.py](https://ctf.csaw.io/files/1f5a0b563b3d325a219db045d856bf5e/forgery.py)

## Solving the challenge

We first notice that the code verifies our triple (answer, $$r$$, $$s$$), before
checking if certain strings appear as a substring as our answer.
```python
    elif verify(answer, r, s, y):
        if b'Felicity' in answer_bytes:
            print("I see you are a fan of Arrow!")
        elif b'Cisco' in answer_bytes:
            print("I see you are a fan of Flash!")
        else:
            print("Brown noser!")
        print(flag)
``` 
Furthermore a mask of the lower 1024 bits is defined and only that is verified against $$r$$ and $$s$$.
```python3
MASK = 2**1024 - 1

...

def verify(answer: str, r: int, s: int, y: int):
    m = int(answer, 16) & MASK 
    if any([x <= 0 or x >= p-1 for x in [m,r,s]]): #hrm s = 0 or -1 is ez
        return False
    return pow(g, m, p) == (pow(y, r, p) * pow(r, s, p)) % p
```

So we can choose any message $$m$$ of up 1024 bits, hide our substring in the upper bits, and come up with an $$r$$ and $$s$$ that satisfies:

$$
g^m \equiv y^r r^s \pmod p
$$

Furthermore, none of our choices of $$m, r, s$$ can be equal to 0 or $$p-1$$, which would easily and trivially satisfy the equation.
However we can choose the next best thing, $$ m = r = s = \frac{p-1}{2}$$. 
By basic number theory, any number to the power of $$\frac{p-1}{2}$$ is either $$1$$ or $$-1$$
mod $$p$$, and these numbers are distributed essentially randomly (not really but for our purposes
they are).

So with a $$50\%$$ chance this choice will work!

Solve script:

```python
from pwn import *
def read_until(s, delim=b':'):
    delim = bytes(delim, "ascii")
    buf = b''
    while not buf.endswith(delim):
        buf += s.recv(1)
    return buf

sock = connect("crypto.chal.csaw.io",5006)
read_until(sock, ':')
read_until(sock, ' ')
p = int(read_until(sock, ' ').strip())
g = int(read_until(sock, ' ').strip())
y = int(read_until(sock, '\n').strip())

phi = p-1
fake = (p-1)//2
msg = b'both'+ l2b(fake)
answer = b2l(msg)
r = fake
s = fake

print(bytes(msg.hex(), 'ascii'))
sock.sendline(bytes(msg.hex(), 'ascii'))
sock.sendline(str(r))
sock.sendline(str(s))
while True:
    print(read_until(sock, '\n'))
```

Flag:

```
flag{7h3_4rr0wv3r53_15_4w350M3!}
```
