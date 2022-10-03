---
title: "[UTCTF 2022] Sunset"
layout: post
keywords: ctf, misc, interactive, algorithm
---

# [UTCTF 2021] Sunset

## tl;dr

Break a **scheme for generating a shared secret** with a cryptosystem relating to some sort of
[discrete fourier transform (DFT)](https://en.wikipedia.org/wiki/Discrete_Fourier_transform).
The solution described here involves **NOT** reversing the values of the keys as probably intended
(which can be done by some linear algebra),
but instead exploits the some of **group properties** of a cyclic array under convolution modulo a prime.

## Description

cryptography/Sunset; 15 solves, 996 points

Challenge author: `oops`

```
subset sumset what did i do Wrap the value of key with utflag{} for the flag.
```

Files: `main.py` and `output.txt`

## The writeup

See writeup I wrote at <https://ubcctf.github.io/2022/03/utctf-sunset/>.
