# yxd

yxd is a hex dump tool similar to xxd, but with features that I wanted. It's written in python3, and doesn't have any requirements outside of the python3 standard library (sys, argparse, re). The script itself is pretty simple, and should be easy to add features to if needed.

## Usage

```
usage: yxd [-h] [-f INFILE] [-o STARTOFFSET] [-s BUFFERSIZE] [-r] [--plain] [--py] [--sc] [--style] [-v]

yxd - Yuu's heX Dumper

optional arguments:
  -h, --help      show this help message and exit
  -f INFILE       File to open
  -o STARTOFFSET  Offset to start within file
  -s BUFFERSIZE   Size of buffer to dump
  -r              Do a reverse hex dump
  --plain         Print in xxd style plain text, compatible with xxd
  --py            Create a python script to generate the buffer
  --sc            Create a C shellcode loader from buffer
  --style         Show Current Hex Style
  -v              Print Version Info
```

### Reading Files

Read a file with command line argument
```
$ yxd -f file.bin
```
You can also read from stdin
```
$ cat file.bin | ./yxd
```

### Specifying offsets and sizes

Specify the beginning offset with the `-o` flag, and the size of the buffer with the `-s` flag. You can use decimal or hex (prefixed with 0x) to represent these numbers.

```
$ ./yxd -f base.bin -o 0x40 -s 0x38
00000040│0100 0000 0500 0000│0000 0000 0000 0000│................
00000050│0000 4000 0000 0000│0000 4000 0000 0000│..@.......@.....
00000060│0000 0000 0100 0000│0000 0000 0100 0000│................
00000070│0000 2000 0000 0000│                   │.. .....
```

### xxd-style Output

yxd is also capable of producing xxd-style hex output with the `--plain` flag.

```
$ yxd -f base.bin --plain
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0200 3e00 0100 0000 7800 4000 0000 0000  ..>.....x.@.....
00000020: 4000 0000 0000 0000 0000 0000 0000 0000  @...............
00000030: 0000 0000 4000 3800 0100 0000 0000 0000  ....@.8.........
00000040: 0100 0000 0500 0000 0000 0000 0000 0000  ................
00000050: 0000 4000 0000 0000 0000 4000 0000 0000  ..@.......@.....
00000060: 0000 0000 0100 0000 0000 0000 0100 0000  ................
00000070: 0000 2000 0000 0000 b03c 66bf 0600 0f05  .. ......<f.....
```

### Reverse Hex Dump

yxd does reverse hex dumps and supports both yxd and xxd style output.

```
$ ./yxd -f base.bin > base.yxd
$ ./yxd -f base.yxd -r
ELF>x@@@8@@ �<f�
```

### Script Generation

One of my main use cases for this tool is to create buffers from files to manipulate them.

```
$ ./yxd -f base.bin --py
```

This dumps the following python script that willwrite the input file and give it a name based on the hash of the file. This is useful if you are doing file format research and need to help track minor changes in files as you edit them. A script form can also make it easier to comment on specific sections, and add your own calculations as needed.

```python
import struct
import sys
import hashlib

def writeBin(b,h):
    outfile = h + ".bin"
    f = open(outfile,'wb')
    f.write(b)
    f.close()
    print(outfile)

b =  b""
b += b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" # 00000000 .ELF............
b += b"\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00" # 00000010 ..>.....x.@.....
b += b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # 00000020 @...............
b += b"\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00" # 00000030 ....@.8.........
b += b"\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # 00000040 ................
b += b"\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00" # 00000050 ..@.......@.....
b += b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00" # 00000060 ................
b += b"\x00\x00\x20\x00\x00\x00\x00\x00\xb0\x3c\x66\xbf\x06\x00\x0f\x05" # 00000070 .. ......<f.....

m = hashlib.sha256()
m.update(b)
shorthash = m.digest().hex()[0:8]
writeBin(b,shorthash)
```

Similarly, the `--sc` option can turn your file buffer into a C program that runs it as shellcode
```
$ ./yxd -f base.bin --sc
```
Gives you the following file.
```c
#include <stdio.h>
#include <string.h>

char code[] = "\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\xb0\x3c\x66\xbf\x06\x00\x0f\x05";

int main() {
    printf("len:%d bytes\n", strlen(code));
    (*(void(*)()) code)();
    return 0;
}
```

## Styling

The yxdconfig.py file contains the style information for each byte, as well as templates for scripts. You can use ANSI escape codes in each, to enable everything from foreground and background colors, to blinking, underline, and more. These are all contained in a big dictionary called `bytez`

Use the `--style` flag to see what the current styling looks like.

## Contributing

PRs are welcome. There are still some features I'd like to add, and I would love to see other people's ideas. There are a lot of hex editing tools out there, but this one fits my usecase for simple, portable hex manipulation, that is also pretty looking.

Twitter: @netspooky
