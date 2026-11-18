---
title: "[Hack.lu 2021] lwsr"
layout: post
keywords: ctf, cryptography, crypto, learning with error, lwe, lfsr, linear-feedback shift register
---

# [Hack.lu CTF 2021] 

## tl;dr

Break a cryptosystem using the [learning with errors (LWE)](https://en.wikipedia.org/wiki/Learning_with_errors) problem and a [linear-feedback shift register (LFSR)](https://en.wikipedia.org/wiki/Linear-feedback_shift_register) by using the fact that the server leaks a bit.

## Description

crypto/lwsr; 20 solves, 285 points

Challenge author: `midao`

Sometimes you learn with errors, but I recently decided to learn with shift registers. Or did I learn with errors over shift registers? Shift registers over errors? Anyway, you may try to shift upwards on the investors board with this.

nc flu.xxx 20075

[zip file](https://flu.xxx/static/chall/lwsr_0c872acfc0b66f185a4968ac3198e067.zip)

## Ingredients of the cryptosystem

Looking through the code there are two pieces of a cryptosystem that were new to me (so I decided to write this blog on it).
The first is a [linear-feedback shift register (LFSR)](https://en.wikipedia.org/wiki/Linear-feedback_shift_register) with a 384-bit `state`, after using the state
it updates it with `state = lfsr(state)`.

```python
def lfsr(state):
    # x^384 + x^8 + x^7 + x^6 + x^4 + x^3 + x^2 + x + 1
    mask   = (1 << 384) - (1 << 377) + 1
    newbit = bin(state & mask).count('1') & 1
    return (state >> 1) | (newbit << 383)
```

Essentially, it generates a bit stream by xoring some bits in the stream to generate the next bit (in this case the last 7 bits and the 384th bit).

The other piece new to me is [learning with errors (LWE)](https://en.wikipedia.org/wiki/Learning_with_errors). 

```
n = 128
m = 384

lwe = Regev(n)
q   = lwe.K.order()
pk  = [list(lwe()) for _ in range(m)] 
sk  = lwe._LWE__s 
```

This generates a secret vector $$s$$, and a list of $$m$$ public key values consisting of a $$n$$ dimensional vector $$v_i$$ and a value $$c_i$$ where the dot product $$s \cdot v_i \approx c_i$$. For these sage commands, we are working in $$\mathbb{F}^n_q$$ for $$q = 16411$$, and approximately equal means some small error according to a discrete gaussian distribution.

Both LWE and LFSR have uses in cryptography.
LFSRs are generate a stream cipher with the right distribution of bits in the output, and can have very long cycles, and is simple to implement (even in hardware) however there are serious flaws with its security.
LWEs is a hard problem that can be the basis of a cryptosystem.

## Cryptanalysis

Looking at the code that does the encryption:
```python
for byte in flag:
    for bit in map(int, format(byte, '#010b')[2:]):
        # encode message
        msg = (q >> 1) * bit
        assert msg == 0 or msg == (q >> 1)

        # encrypt
        c = [vector([0 for _ in range(n)]), 0]
        for i in range(m):
            if (state >> i) & 1 == 1:
                c[0] += vector(pk[i][0])
                c[1] += pk[i][1]

        # fix ciphertext
        c[1] += msg
        print(c)

        # advance LFSR
        state = lfsr(state)
```

The code encrypts each bit of the string by computing $$v = \sum_{i\in L} v_i$$ where $$L$$ are the on bits in the LFSR and computing the corresponding approximate $$c = \sum_{c_i\in L} c_i$$, and adding `q >> 1` in $$\mathbb{F}_q$$ if the bit is on. 
Note that $$c$$ is approximate, but the sum of a gaussian distribution is still a gaussian distribution with a wider distribution, so it is still approximately correct.

Afterwards, the server let's us encode our own messages bit by bit, and checks if it is correct.

```python
while True:
    # now it's your turn :)
    print("Your message bit: ")
    msg = int(sys.stdin.readline())
    if msg == -1:
        break
    assert msg == 0 or msg == 1

    # encode message
    pk[0][1] += (q >> 1) * msg

    # encrypt
    c = [vector([0 for _ in range(n)]), 0]
    for i in range(m):
        if (state >> i) & 1 == 1:
            c[0] += vector(pk[i][0])
            c[1] += pk[i][1]

    # fix public key
    pk[0][1] -= (q >> 1) * msg

    # check correctness by decrypting
    decrypt = ZZ(c[0].dot_product(sk) - c[1])
    if decrypt >= (q >> 1):
        decrypt -= q
    decode = 0 if abs(decrypt) < (q >> 2) else 1
    if decode == msg:
        print("Success!")
    else:
        print("Oh no :(")

    # advance LFSR
    state = lfsr(state)
```

This seems fine, and in fact some local testing shows that decryption should work with very high probability, as the error for the sum of bits should be rather small.
On closer inspection however, this second encryption is not implemented properly, instead
of the ciphertext being modified when the bit is on, the value of the first vector is modified by `pk[0][1] += (q >> 1) * msg`. Meaning, if the first bit of the LFSR is a 0, but the encrypted message is a 1, there WILL be an error!

This means, by asking the server to encrypt a 1, the output of the server will leak the 0th bit of the LFSR. Since the LFSR shifts all the bits each time, if we query the server 384 times, we will recover all the bits of the LFSR.

However, recovering the LFSR is not enough, since it changes every time, we need to be able to recover the previous state of the LFSR.
Fortunately by looking at the equation of the last bit, we can easily recover the first bit we lost in the shift, so the LFSR is performing an invertible operation.
```python
def revlfsr(state):
    mask   = (1 << 384) - (1 << 376) 
    newbit = bin(state & mask).count('1') & 1
    return ((state << 1) | (newbit)) & ((1<<384) -1)
```

And now we're done! We know the full state of the LFSR, so if we try encrypting using the same scheme, if the value we compute by summing the corresponding values $$c_i$$ in the public key is exactly equal, than we know that bit is 0, otherwise, we should be off by exactly `q >> 1`($$8205$$), so we are done without having to deal with any vector operations at all!

Doing this gives us the flag!
```
flag{your_fluxmarket_stock_may_shift_up_now}
```

Note that there were other linear algebra solutions based on the structure of the LFSR, including those that didn't need to send ANY queries to the server. This is because we have an exact sum of vectors, so we can solve directly for the internal state of the LFSR.
On the other hand my solution didn't even look at a single vector!

Full solve script:
```python
from sage.all import *
from pwn import *

def read_until(s, delim=b'='):
    delim = bytes(delim, "ascii")
    buf = b''
    while not buf.endswith(delim):
        buf += s.recv(1)
    print("[+] READING: ", buf)
    return buf

sock = connect("flu.xxx", 20075)

def lfsr(state):
    # x^384 + x^8 + x^7 + x^6 + x^4 + x^3 + x^2 + x + 1
    mask   = (1 << 384) - (1 << 377) + 1
    newbit = bin(state & mask).count('1') & 1
    return (state >> 1) | (newbit << 383)

def revlfsr(state):
    mask   = (1 << 384) - (1 << 376) 
    newbit = bin(state & mask).count('1') & 1
    return ((state << 1) | (newbit)) & ((1<<384) -1)

n = 128
m = 384
q = 16411

read_until(sock, '\n') # first line saying something about q
exec(b'pk = ' + read_until(sock,'\n').strip())

read_until(sock, '\n') # some nonsense that doesn't matter

c = []
read_colon = False
inp = read_until(sock, ':')
for l in inp.split(b'\n'):
    print(l)
    if b':' in l:
        break
    exec(b'c.append('+l.strip()+b')')

state = 0
for _ in range(384):
    sock.sendline(b'1')
    resp = read_until(sock, ':') # end of : line
    if b'Oh no' not in resp:
        state |= (1<<_)
    else:
        # end of : line, because we read to the first colon of :(
        read_until(sock, ':') 

# unwind the "cleared" LFSR bits
for _ in range(384):
    state = revlfsr(state)

# unwind all the used LFSR bits
for _ in range(len(c)):
    state = revlfsr(state)

ans = ""
cum = ""
for v, x in c:
    true_val = sum([k[1] if ((state>>i)&1) else 0 for i, k in enumerate(pk)])%q
    diff = int(true_val) - int(x)
    if diff >= (q>>1):
        diff -= q
    cum += "0" if abs(diff) < (q >>2) else "1"
    if (len(cum)>=8):
        ans +=chr(int(cum, 2))
        cum = ""
    state = lfsr(state)

print(ans)
```

