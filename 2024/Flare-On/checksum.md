---
title: chall 2 on flareon24
description: 
tags:
  - "#strings"
  - CTF
  - reverse_engeneering
  - golang
  - DMGPT
  - writeup
CTF: flareon24
challenge: checksum
kathegorie: rev
questions:
  - how to analyse golang files?
  - how to find main in golang files?
---
[[2023-04-09 - Lab Einführung|<< vorherige Veranstaltung]] | [[2023-04-11 - Malware 1|nächste Veranstaltung >>]]

---


# Prerequisites
- floss
- ghidra


# Analysis
## Run It
1. first we test what the programm is doing
2. running the programm 
	1. FLARE-VM 11/11/2024 15:28:17
```
.\checksum.exe
Check sum: 5219 + 7337 = sdafas
Not a valid answer...

.\checksum.exe
Check sum: 8214 + 2502 = 10719
Try again! ;)

.\checksum.exe
Check sum: 6463 + 5165 = 11628
Good math!!!

Check sum: 9695 + 5797 = 15492
Good math!!!
```



as we see in the picture we get an math question

wrong answer: try again -> programm closing
letters: Not a valid answer -> programm closing
wrigt answer: Good math!!! -> next question

# RE

### Strings
to get the strings we run floss

```floss E:\knowledge base\CTF\FlareOn24\Chall2\checksum.exe```  [[Floss - Analysing Strings]]

as we see in the result its an golang written programm

```
golang.org/x/sys/cpu..inittask 
golang.org/x/sys/cpu.Initialized
golang.org/x/sys/cpu.X86 
golang.org/x/sys/cpu.options 
golang.org/x/sys/cpu.getAuxvFn
```


as we have a lots of strings we ask dmgpt if can show us some important strings:
the result:

we get a few strings include this: (probs to DMGPT)

```
cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA==

\REAL_FLAREON_FLAG.JPG

FlareOn2024

```


first one looks like an base64 string we decode it with:
```
cat cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA== | base64
```


and we get this?

```
flarevm:~$ echo cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA== | base64 -d
q
R{^PTU'ZPXPTQPERyZU$]A]}[VT
```

### Ghidra

#### Finding Main

as we have an golang programm its much easier to find main :)
we only need to go to namespaces -> ma

![[Pasted image 20241111161625.png]]

so we make live easer and ask dmgpt what happens in it this time gmpt overanalyzed it a bit, but we could figure out this together with dmgpt


1. it starts by generate a random number
2. and reads the user input
![[Pasted image 20241111162139.png]]

so we give em a new name 
randomnumber![[Pasted image 20241111162226.png]]

user_input![[Pasted image 20241111163735.png]]
![[Pasted image 20241111163735.png]]

next we set an counter in the picture aboce iVar4 = 0
this is an counter for the wrigt answers. and we go in an while loop as long as the counter is random number +3

![[Pasted image 20241111162728.png]]


this is pretty interresting as we didnt see this in the intial programm running in the first step
so we have to run give em a lots of time the wrigt answer?
next it generates two more random numbers (less then 10k and gets the sum)
![[Pasted image 20241111163121.png]]
![[Pasted image 20241111163145.png]]



there is lots of more stuff in hree and dmgpt can explain everything but dldr this is all interesing.. but when we scroll more down we find our output here it can get more interesting

we see main.b is here for error handling

next we see an if. the if check if the user input matches the random_number1_2
if no we get an try again
![[Pasted image 20241111163925.png]]


else we get an good math and the counter for wright answer +1

![[Pasted image 20241111164147.png]]

if the break out the while (means counter with wright answers is more than random number +3) we can input something new (ignore the name in the var as we dont know jed its an checksum ;))
![[Pasted image 20241111165724.png]]

when we scroll down a bit it gets more interesting

when main.a says the input string is correct we run 

```
os::os.UserCacheDir();
REAL_FLAREON_FLAG.JPG"
```

so we can asume we need ne enter the write string after the write maths question to get the flag in the picture
![[]]
![[Pasted image 20241111170255.png]]


lets enter main.a to checks what main.a does
so we let dmgpt does it magic:

It starts a counter by lenght of the input string:

![[Pasted image 20241111171147.png]]
next we go in an while loop until the lenght of the string is equal an other variable

![[Pasted image 20241111171329.png]]


At the bottom of the loop , it loops over the input (base64 string wee saw in floss and here ) XORing it by characters from a global static string, “FlareOn2024”:

![[Pasted image 20241111171448.png]]

at the bottom of the loop we see (or dmgpt sees ;) ) an xor troutgh base64
 
and loops infinitely, but then has an `if` in the loop checking to see if it’s looped over the entire string [2]. If so, it does stuff and returns.

At the bottom of the loop [3], it loops over the input XORing it by characters from a global static string, “FlareOn2024”:

![[Pasted image 20241111171701.png]]
I asume this is the string we saw bevore - an stack string and this is the key for the base64 fild


### solving the challenge

what to we have?

we know:

there are a random number of math questions which we have to answer right
after this wee need to enter the wrigt string. for getting the picture

the wriight string should be an xor encrypted string key FlareOn2024 and string is the base64 string cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA==


lets do this in python and dmgpt


```
flarevm:~$ encoded = "cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA=="
^Cflarevm:~$ python3
Python 3.10.12 (main, Jul 29 2024, 16:56:48) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
>>>
>>>
>>> encoded = "cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA=="

>>> from base64 import b64decode
>>> enc_key = b64decode(encoded)
>>> from itertools import cycle
>>> ''.join(chr(x^y) for x,y in zip(enc_key, cycle(b'FlareOn2024')))

```
and we get this string

now we know its en checksum what he wants :)

open the file

According to [Golang docs](https://pkg.go.dev/os#UserCacheDir), the file must be in `%LocalAppData%` on Windows. as os.UserCacheDir() this is de default path



![[Pasted image 20241111173259.png]]