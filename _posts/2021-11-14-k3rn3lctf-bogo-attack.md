---
title: "[K3RN3L CTF 2021] BogoAttack"
layout: post
keywords: ctf, misc, interactive, algorithm
---

# [K3RN3L CTF 2021] BogoAttack

## tl;dr

Find the order of a permutation of size $$10^4$$ stored in an array
with an oracle that is able to get the contents
of a subset of indices of the array but randomly shuffles the contents before returning.
There is a limit of $$15$$ queries.
Solve by a divide and conquer/parallel binary search algorithm.

## Description

misc/BogoAttack; 26 solves, 446 points

Challenge author: `DrDoctor`

Someone attacced by Bogo! I must seek revenge. Now is the time to attacc back!

[main.py](https://flu.xxx/static/chall/lwsr_0c872acfc0b66f185a4968ac3198e067.zi://ctf.k3rn3l4rmy.com/kernelctf-distribution-challs/bogo-attack/main.py)

## First impressions of the problem

This problem was actually first given as `Bogo Solve` where the query limit was
accidentally not enforced. 
I didn't notice and solved this problem (and later only modified the port
of the server in my solve script). 
I'll walk through my first thoughts on the problem assuming the limit was
actually enforced.

We're given the following python script that's running on the server:

```python
import random
NUMS = list(range(10**4))
random.shuffle(NUMS)
tries = 15
while True:
    try:
        n = int(input('Enter (1) to steal and (2) to guess: '))
        if n == 1:
            if tries==0:
                print('You ran out of tries. Bye!')
                break
            l = map(int,input('Enter numbers to steal: ').split(' '))
            output = []
            for i in l:
                assert 0<= i < len(NUMS)
                output.append(NUMS[i])
            random.shuffle(output)
            print('Stolen:',output)
            tries-=1
        elif n == 2:
            l = list(map(int,input('What is the list: ').split(' ')))
            if l == NUMS:
                print(open('flag.txt','r').read())
                break
            else:
                print('NOPE')
                break
        else:
            print('Not a choice.')
    except:
        print('Error. Nice Try...')
```

I got pretty excited when I saw the question, as a former competitive programmer (or maybe I still am one?) and a computer science theory student.
(So excited that I probably spent ten times longer writing this writeup than 
actually solving and coding a solution.)
I immediately recognize this as an interactive competitive programming question. 
(This might have seen this exact one on [Codeforces](https://codeforces.com/) or
[AtCoder](https://atcoder.jp/) but interactive problems are pretty rare, and my memory is fuzzy)
The question can be summarized as follows:

> Given a permutation of size $$10^4$$ in an array and access to the array
> via an oracle 
> that is able to get the contents of a subset of indices of the array 
> but randomly shuffles the contents before returning.
> Find the contents in at most $$15$$ queries.

First we note that $$15$$ is more or less $$\log_2(10^4)$$,
 so we want to make logarithmically many queries. 
This suggests some sort of divide and conquer solution.
But what exactly are we dividing here? 

## A Divide and Conquer approach

Let's think about what we can accomplish with one query.
We can split the array down the middle and query all the indices
in the first half as pictured below. What does this give us?

![dc1](/assets/images/k3rn3lctf2021/bogoattack/DC1.png)

The server would tell us which elements are in the first half,
which (by simple deduction) would tell us the rest of the elements
are in the second half.
Now we can treat these two halves of the array as two seperate problems
in and of themselves and do the same thing.

![dc2](/assets/images/k3rn3lctf2021/bogoattack/DC2.png)

For each of these subproblems we can repeat again, and 
continue until we know exactly where every element is!

![dc3](/assets/images/k3rn3lctf2021/bogoattack/DC3.png)

However, naively this would give us a lot of queries,
in particular, if we let $$Q(n)$$ denote the number of queries
needed to solve the problem on an array of size $$n$$, 
we essentially found the following recurrence:

$$ Q(n) = 2 Q(n/2) + 1 $$

Unfortuantely this solves to $$Q(n) = n$$, which is no better than
querying each position individually!
We need one more idea to help us out.
What if we send the queries for all our subproblems of the 
same size simultaneously?

Since the elements involved in each subproblem form a partition of our
original elements, it doesn't matter that we get the elements in a random order,
we already **know** which elements are from each subproblem.
This means we can solve the problem with the recurrence of:

$$ Q(n) = Q(n/2) + 1  = \lfloor \log_2 n \rfloor$$

However, coding a solution like this seems complicated, how do we maintain
all these subproblems?

## Another way of looking at things

Let's take a step back and look at what we're learning from each we make.
For simplicity, let's actually assume that we are working with a permutation
of size $$2^{14}$$ elements ($$16384$$)
instead of $$10^4$$ elements. We'll see why this makes things easier in a bit.

Let's look at the first query to a problem:

![dc1](/assets/images/k3rn3lctf2021/bogoattack/DC1.png)

Querying for which elements are in the first half of the array is 
essentially looking at what elements have the index of the first bit
be $$0$$. The rest of the numbers have first bit $$1$$.
So a query can learn the most significant bit of the **positions** of all the numbers 
in the list!

In fact, there was nothing special about chooosing the first half,
the positions with most siginficant bit $$0$$.
We could just as easily
have chosen every position with a $$0$$ in the $$k$$th bit for some $$1\le k \le 14$$
and learn that bit for every element in the permutation!

So this suggests another algorithm, for each bit, learn the $$k$$th bit of 
every element for every $$k$$.
If you examine this new algorithm closely, this would make the same queries
as the divide and conquer algorithm we had before!

This is a fairly common phenomenon, when doing binary divide and conquer,
we can instead view it in terms of the bits of the number and work with those for a
much simpler to code algorithm 
(this forms the basis of things like [segment trees](https://codeforces.com/blog/entry/18051)).

We can view this as a form of parallel binary search, for every element of
the permutation, we are finding
its position in the list via binary search.
Cleverly, we're able to do this for all 
elements at once!

This is what I ended up coding:
```python
from pwn import *

def read_until(s, delim=b'='):
    delim = bytes(delim, "ascii")
    buf = b''
    while not buf.endswith(delim):
        buf += s.recv(1)
    print("[+] READING: ", buf)
    return buf

sock = connect("ctf.k3rn3l4rmy.com", 2247)


NUMS = [0]*(10**4)
POS  = [0]*(10**4)

for i in range(14):
    inp = read_until(sock, ':')
    sock.sendline(b'1')
    inp = read_until(sock, ':')
    output = ""
    for j in range(10**4):
        if j>>i&1:
            output += str(j) + " "
    sock.sendline(output[:-1])
    inp = read_until(sock, '[')
    inp = read_until(sock, ']')[:-1].split(b', ')
    nums = [int(x) for x in inp]
    for x in nums:
        POS[x]+=1<<i

for x in range(10**4):
    NUMS[POS[x]] = x

output = ""
for x in NUMS:
    output += str(x) + " "
sock.sendline('2')
sock.sendline(output[:-1])
sock.interactive()
```

