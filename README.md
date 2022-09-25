# yxd

yxd is a hex dump tool similar to xxd, but with features that I wanted. It's written in python3, and doesn't have any requirements outside of the python3 standard library (sys, argparse, re). The script itself is pretty simple, and should be easy to add features to if needed.

## Usage

```
usage: yxd.py [-h] [-f INFILE] [-o STARTOFFSET] [-s BUFFERSIZE] [-r] [--plain] [--xx] [--ps] [--py] [--sc] [--style] [-v]

yxd - Yuu's heX Dumper

optional arguments:
  -h, --help      show this help message and exit
  -f INFILE       File to open
  -o STARTOFFSET  Offset to start within file
  -s BUFFERSIZE   Size of buffer to dump
  -r              Do a reverse hex dump
  --plain         Print in xxd style plain text, compatible with xxd
  --xx            Print in xx format, a modified xxd-style dump for use with xx
  --ps, -ps       output in postscript plain hexdump style.
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
$ yxd -f base.bin -o 0x40 -s 0x38
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

### xx Compatible Hex Dump 

yxd can create .xx files compatible with the [xx project](https://github.com/netspooky/xx) by using the flag `--xx`. These are modified xxd style hex dumps with the offset on the side within an `xx` comment, to allow for editing and markup while retaining offset data and the ASCII dump of the file.

```
$ yxd -f png.5e86c4ab.bin --xx
8950 4e47 0d0a 1a0a 0000 000d 4948 4452  ; 00000000: .PNG........IHDR
0000 0001 0000 0001 0100 0000 0037 6ef9  ; 00000010: .............7n.
2400 0000 1049 4441 5478 9c62 6001 0000  ; 00000020: $....IDATx.b`...
00ff ff03 0000 0600 0557 bfab d400 0000  ; 00000030: .........W......
0049 454e 44ae 4260 82                   ; 00000040: .IEND.B`.
```

### Plain Hex Dump

This is a plain hex dump with all the hexbytes as one long line. This is equivalent to the xxd flag `-ps`. You can use `-ps` or `--ps` to produce this.

```
$ yxd -f png.5e86c4ab.bin -ps 
89504e470d0a1a0a0000000d4948445200000001000000010100000000376ef9240000001049444154789c626001000000ffff03000006000557bfabd40000000049454e44ae426082
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
$ ./yxd -f base.bin -o 0x78 --sc
```

This grabs the shellcode of this specific binary and turns it into a dropper.

```c
#include <stdio.h>
#include <string.h>

char code[] = "\xb0\x3c\x66\xbf\x06\x00\x0f\x05";

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

Twitter: [@netspooky_](https://twitter.com/netspooky_)
