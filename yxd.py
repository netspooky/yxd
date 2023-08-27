#!/usr/bin/env python3
import sys
import argparse
import re
import yxdconfig as yc

parser = argparse.ArgumentParser(description="yxd - Yuu's heX Dumper")
parser.add_argument('-f', help='File to open', dest='inFile')
parser.add_argument('input', help='File to open', nargs='?')
parser.add_argument('-o', help='Offset to start within file', dest='startOffset', type=lambda x: int(x,0) )
parser.add_argument('-s', help='Size of buffer to dump', dest='bufferSize', type=lambda x: int(x,0) )
parser.add_argument('-r', help='Do a reverse hex dump',  dest='reverseDump', action="store_true")
parser.add_argument('--plain', help='Print in xxd style plain text, compatible with xxd', dest='plainText', action="store_true")
parser.add_argument('--xx', help='Print in xx format, a modified xxd-style dump for use with xx', dest='xxFormat', action="store_true")
parser.add_argument('--ps','-ps', help='output in postscript plain hexdump style.', dest='psFormat', action="store_true")
parser.add_argument('--py', help='Create a python script to generate the buffer', dest='genPythonScript', action="store_true")
parser.add_argument('--sc', help='Create a C shellcode loader from buffer', dest='genShellcode', action="store_true")
parser.add_argument('--style', help='Show Current Hex Style', dest='dumpStyle', action="store_true")
parser.add_argument('-v', help='Print Version Info', dest='printVersion', action="store_true")

versionInfo="yxd - Yuu's heX Dumper Version 20230827.0"""

def styleDump():
    """
    Dump all styles.

    Dump the color and style information from the yxdconfig
    """
    for i in range(0,256):
        print(f"{yc.bytez[i]}{i:02X}{yc.EOA} ",end="")
        if (i+1) % 16 == 0:
            if i == 0:
                continue
            else:
                print()

def dump(inBytes,baseAddr=0,dataLen=0,blockSize=16,outFormat="yxd"):
    """
    Dump hex.

    This function performs a hex dump on the provided buffer with
    the given parameters

    Parameters
    ----------
    inBytes : bytes
        The hex text buffer to work with.
    baseAddr : int
        The base address of the buffer
    dataLen : int
        The length of data to dump from the buffer. Default 0 = All
    blockSize : int
        The number of bytes per line
    outFormat : str
        The format of hex dump format to do
    """
    dataLen = len(inBytes) if ( dataLen == 0 ) or ( dataLen > len(inBytes) ) else dataLen # Sanity check
    offs = 0 
    if ( outFormat == "xxd" ) or ( outFormat == "xx") or ( outFormat == "ps"):
        yc.bytez = {}
        yc.OFFSTYLE = ""
        yc.SEP0  = ": "
        yc.SEP1  = " "
        yc.SEP2  = "  "
        yc.EOA  = ""
    while offs < dataLen:
        try:
            hb = []
            bAsc = ""
            bChunk = inBytes[offs:offs+blockSize]
            chunkBytes = 0
            for b in bChunk:
                bFmt = f"{yc.bytez[b]}" if b in yc.bytez.keys() else ""
                bAsc += f"{bFmt}{chr(b)}{yc.EOA}" if chr(b).isprintable() and b < 0x7F else f"{bFmt}.{yc.EOA}"
                hb.append(f"{bFmt}{b:02x}{yc.EOA}")
                chunkBytes = chunkBytes + 1
            if chunkBytes < blockSize:
                neededChunks = blockSize - chunkBytes
                for nullChunk in range(neededChunks):
                    hb.append("  ")
            realOffs = offs+baseAddr
            # This is where the buffer to print is built
            offsetOut = f"{yc.OFFSTYLE}{realOffs:08x}{yc.EOA}{yc.SEP0}"
            hexOut =  f"{hb[0]}{hb[1]} "
            hexOut += f"{hb[2]}{hb[3]} "
            hexOut += f"{hb[4]}{hb[5]} "
            hexOut += f"{hb[6]}{hb[7]}{yc.SEP1}"
            hexOut += f"{hb[8]}{hb[9]} "
            hexOut += f"{hb[10]}{hb[11]} "
            hexOut += f"{hb[12]}{hb[13]} "
            hexOut += f"{hb[14]}{hb[15]}{yc.SEP2}"
            if outFormat == "xx":
                print(f"{hexOut}; {offsetOut}{bAsc}")
            elif outFormat == "ps":
                print("".join(hexOut.split()),end="")
            else:
                print(f"{offsetOut}{hexOut}{bAsc}")
            offs = offs + blockSize
        except Exception as e:
            print(f"yxd.dump: {e}")
    if outFormat == "ps":
        print() # Avoid annoying terminal behavior with a new line

def hexString(bChunk):
    """
    Create an escaped hex string.

    This function performs turns a buffer of binary data into a
    hex string in the style of "\x41\x41\x41\x41"

    Parameters
    ----------
    inBytes : bytes
        The hex text buffer to work with.

    Returns
    -------
    bHex : str
        the hex string with double quotes around it
    bAsc : str
        printable characters in this buffer, if any
    cSum : int
        checksum, used to determine if all bytes were 0
    """
    bHex = ""
    bAsc = ""
    cSum = 0
    try:
        for b in bChunk:
            bAsc += chr(b) if chr(b).isprintable() and b < 0x7F else '.'
            bHex += f"\\x{b:02x}"
            cSum = cSum + b
        bHex = f"\"{bHex}\""
        return bHex, bAsc, cSum
    except Exception as e:
        print(f"yxd.hexString: {e}") # Maybe don't need
        return bHex, bAsc, cSum

def genPythonScript(inBytes):
    """
    Create a Python script loader.

    This function performs turns a buffer of binary data into a
    python script that creates a copy of your binary data.

    Parameters
    ----------
    inBytes : bytes
        The hex text buffer to work with.
    """
    print(yc.template1)
    offs = 0
    zeroCount = 0
    savedOffset = 0
    while offs < len(inBytes):
        bChunk = inBytes[offs:offs+16]
        chunkLen = len(bChunk)
        bHex, bAsc, cSum = hexString(bChunk)
        bHex = "b" + bHex
        if cSum == 0:
            if savedOffset == 0:
                savedOffset = offs
            zeroCount = zeroCount + chunkLen
        else:
            if zeroCount != 0:
                print(f'b += b"\\x00"*{zeroCount} # {savedOffset:08X}')
                zeroCount = 0
                savedOffset = 0
            print(f"b += {bHex} # {offs:08X} {bAsc}")
        offs = offs + 16
    if zeroCount != 0:
        print(f'b += b"\\x00"*{zeroCount} # {savedOffset:08X}')
    print(yc.template2)

def genShellcode(inBytes):
    """
    Create a C shellcode loader.

    This function performs turns a buffer of binary data into a
    C-style shellcode loader.

    Parameters
    ----------
    inBytes : bytes
        The hex text buffer to work with.
    """
    print(yc.cTemplate1)
    print("char code[] = ",end="")
    scBuff, scAsc, scSum = hexString(inBytes)
    print(f"{scBuff};")
    print(yc.cTemplate2)

def reverseDump(inText):
    """
    Reverse hex dump.

    This function performs a reverse hex dump from a text buffer.
    It can detect both xxd and yxd style hex dumps and convert them
    back into binary buffers.

    Parameters
    ----------
    inText : bytes
        The hex text buffer to work with.
    """
    hexBuf = b""
    if inText[0] == 0x1b:
        # yxd Ansi output
        linebuf = inText.decode("utf-8")
        lines = linebuf.split("\n")
        for l in lines:
            try:
                l = l.split("│")
                l = l[1] + l[2]
                l = l.replace(" ", "")
                escAnsi = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                l = escAnsi.sub('', l)
                l = bytes.fromhex(l)
                hexBuf += l
            except:
                break
    elif inText[0:8] == b"00000000":
        # xxd style output
        linebuf = inText.decode("latin-1")
        lines = linebuf.split("\n")
        for l in lines:
            try:
                l = l.split("  ") # Shave off the last part
                l.pop()
                l = l[0].split(": ")
                l = l[1]
                l = l.replace(" ", "")
                l = bytes.fromhex(l)
                hexBuf += l
            except:
                break
    else:
        print("yxd.reverseDump: Wrong Format!")
    sys.stdout.buffer.write(hexBuf)
    return

class yxd:
    """
    A class to represent a buffer of binary data.

    The yxd class creates a reusable object that can access the features of the yxd library.

    ...

    Attributes
    ----------
    binData : bytes
        a buffer of binary data
    amount : int
        the amount of data to output, 0 = all
    baseAddr : int
        the base address of the binary data
    outFormat : str
        output format, xx, xxd, yxd, python, shellcode, ps etc
    color : str
        the color scheme from the config options
    blockSize : int
        how many bytes per line
    offset : int
        offset within the buffer to do the hexdump from
    quiet : bool
        whether to dump to the terminal or not

    Methods
    -------
    dump():
        do hex dump on the binary data with configured settings
    genPythonScript():
        generate a python script that creates a copy of your binary data
    genShellcode():
        create a C shellcode loader from binary data
    reverseDump():
        do a reverse hex dump
    """
    def __init__(self, binData, amount=0, baseAddr=0, outFormat="xxd", color="default", blockSize=16, offset=0,  quiet=False ):
        self.binData = binData
        self.dataLen = len(binData)
        self.baseAddr = baseAddr
        self.outFormat = outFormat
        self.color = color
        self.offset = offset
        self.blockSize = blockSize
        self.amount = amount
        self.quiet = quiet
        if quiet != True:
            self.dump()
    def styleDump(self):
        for i in range(0,256):
            print(f"{yc.bytez[i]}{i:02X}{yc.EOA} ",end="")
            if (i+1) % 16 == 0:
                if i == 0:
                    continue
                else:
                    print()
    def dump(self):
        dump(self.binData,self.baseAddr,self.dataLen,self.blockSize,self.outFormat)
    def genPythonScript(self):
        genPythonScript(self.binData)
    def genShellcode(self):
        genShellcode(self.binData)
    def reverseDump(self):
        reverseDump(self.binData)

if __name__ == '__main__':
    args = parser.parse_args()

    if args.printVersion:
        print(versionInfo)
        sys.exit(0)
    if args.dumpStyle:
        styleDump()
        sys.exit(0)

    hexStyle = "yxd"
    if args.plainText:
        hexStyle = "xxd"
    if args.xxFormat:
        hexStyle = "xx"
    if args.psFormat:
        hexStyle = "ps"

    bufferSize  = args.bufferSize  if args.bufferSize else 0
    startOffset = args.startOffset if args.startOffset else 0
    if args.inFile == None:
        args.inFile = args.input
    if args.inFile and args.inFile != "-":
        inFile = args.inFile
        with open(inFile,"rb") as f:
            f.seek(startOffset)
            binData = f.read(bufferSize) if bufferSize !=0 else f.read()
            binSize = len(binData)
    else:
        binData = sys.stdin.buffer.read()
        binSize = len(binData)

    yxdd = yxd(binData, baseAddr=startOffset, outFormat=hexStyle, quiet=True)
    if args.genPythonScript:
        yxdd.genPythonScript()
    elif args.genShellcode:
        yxdd.genShellcode()
    elif args.reverseDump:
        yxdd.reverseDump()
    else:
        yxdd.dump()
