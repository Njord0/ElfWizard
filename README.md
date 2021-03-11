# ElfWizard
A simple tool to inject shellcode into an ELF binary.

## Requirements
* gcc
* A ELF binary (no PIE)

## Installation
<details>
    <summary>How to install</summary>
    
    git clone https://github.com/njord0/elfwizard
    cd elfwizard
    gcc -o elfwizard src/* -Iincludes/
</details>

## Examples

<details>
    <summary>Code injection on 64 bits binary</summary>
<p>
I will use test/test.c for this example,<br/>
first we need to compile the binary:

    gcc -o test.bin test/test.c -fno-pie -no-pie
    
We are now ready to inject the shellcode, I wrote a 
simple shellcode that prints "Hello world". (<a href="test/hellox64.asm">Here</a>)

    ./elfwizard --inject 4831c050b8726c640a5048b848656c6c6f20776f50b801000000bf010000004889e6ba0d0000000f05 test.bin

Now we can execute the binary :
    
    $ ./test.bin
    Hello world
    A simple program that display his name and PID
    test.bin : 49686

</p>
</details>

<details>
    <summary>Code injection on 32 bits binary</summary>
<p>
I will use test/test.c for this example,<br/>
first we need to compile the binary:

    gcc -o test.bin test/test.c -fno-pie -no-pie -m32
    
We are now ready to inject the shellcode, I wrote a 
simple shellcode that prints "Hello world". (<a href="test/hellox86.asm">Here</a>)

    ./elfwizard --inject 31c05068726c640a686f20776f6848656c6c89e1b804000000bb01000000ba0c000000cd80 test.bin

Now we can execute the binary :
    
    $ ./test.bin
    Hello world
    A simple program that display his name and PID
    test.bin : 51237

</p>
</details>
