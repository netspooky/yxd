#!/usr/bin/env python3
import sys
import argparse
import re
import yxdconfig as yc

parser = argparse.ArgumentParser(description="yxd - Yuu's heX Dumper")
parser.add_argument('-f', dest='inFile', help='File to open')
parser.add_argument('input', help='File to open', nargs='?')
parser.add_argument('-o', type=lambda x: int(x,0), dest='startOffset', help='Offset to start within file')
parser.add_argument('-s', type=lambda x: int(x,0), dest='bufferSize', help='Size of buffer to dump')
parser.add_argument('-r', dest='reverseDump', help='Do a reverse hex dump',action="store_true")
parser.add_argument('--plain', dest='plainText', help='Print in xxd style plain text, compatible with xxd',action="store_true")
parser.add_argument('--xx', dest='xxFormat', help='Print in xx format, a modified xxd-style dump for use with xx',action="store_true")
parser.add_argument('--ps','-ps', dest='psFormat', help='output in postscript plain hexdump style.',action="store_true")
parser.add_argument('--py', dest='makePyScript', help='Create a python script to generate the buffer',action="store_true")
parser.add_argument('--sc', dest='makeShellcode', help='Create a C shellcode loader from buffer',action="store_true")
parser.add_argument('--style', dest='dumpStyle', help='Show Current Hex Style',action="store_true")
parser.add_argument('-v', dest='printVersion', help='Print Version Info',action="store_true")

versionInfo="""
yxd - Yuu's heX Dumper
Version 20230216.0
"""
def styleDump():
    for i in range(0,256):
        print(f"{yc.bytez[i]}{i:02X}{yc.EOA} ",end="")
        if (i+1) % 16 == 0:
            if i == 0:
                continue
            else:
                print()
    sys.exit(0)

def dHex(inBytes,baseOffs,dataLen,blockSize,hexStyle):
    # This is the main hex dump function containing the style and layout features.
    offs = 0 
    if ( hexStyle == "xxd" ) or ( hexStyle == "xx") or ( hexStyle == "ps"):
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
            realOffs = offs+baseOffs
            # This is where the buffer to print is built
            offsetOut = f"{yc.OFFSTYLE}{realOffs:08X}{yc.EOA}{yc.SEP0}"
            hexOut =  f"{hb[0]}{hb[1]} "
            hexOut += f"{hb[2]}{hb[3]} "
            hexOut += f"{hb[4]}{hb[5]} "
            hexOut += f"{hb[6]}{hb[7]}{yc.SEP1}"
            hexOut += f"{hb[8]}{hb[9]} "
            hexOut += f"{hb[10]}{hb[11]} "
            hexOut += f"{hb[12]}{hb[13]} "
            hexOut += f"{hb[14]}{hb[15]}{yc.SEP2}"
            if hexStyle == "xx":
                print(f"{hexOut}; {offsetOut}{bAsc}")
            elif hexStyle == "ps":
                print("".join(hexOut.split()),end="")
            else:
                print(f"{offsetOut}{hexOut}{bAsc}")
            offs = offs + blockSize
        except Exception as e:
            print(e)
            sys.exit(1)
    if hexStyle == "ps":
        print() # Avoid annoying terminal behavior with a new line

def dumpHexString(bChunk):
    # Generates a hex string in the style of \x00\x01\x02\x03
    # Returns this string, the corresponding ascii, and whether or not all bytes were 0
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
        print(e)
        sys.exit(1)

def genPythonScript(inBytes):
    print(yc.template1)
    offs = 0
    zeroCount = 0
    savedOffset = 0
    while offs < len(inBytes):
        bChunk = inBytes[offs:offs+16]
        chunkLen = len(bChunk)
        bHex, bAsc, cSum = dumpHexString(bChunk)
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
    print(yc.cTemplate1)
    print("char code[] = ",end="")
    scBuff, scAsc, scSum = dumpHexString(inBytes)
    print(f"{scBuff};")
    print(yc.cTemplate2)

def reverseDump(inBytes):
    # Reverse dump a text buffer, you can do xxd style or yxd style with a │ delimiter.
    hexBuf = b""
    if inBytes[0] == 0x1b:
        # yxd Ansi output
        linebuf = inBytes.decode("utf-8")
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
    elif inBytes[0:8] == b"00000000":
        # xxd style output
        linebuf = inBytes.decode("latin-1")
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
        print("Wrong Format!")
    sys.stdout.buffer.write(hexBuf)
    return

if __name__ == '__main__':
    args = parser.parse_args()

    if args.inFile == None:
        args.inFile = args.input

    hexStyle = "yxd"          # Default style
    if args.plainText:
        hexStyle = "xxd"
    if args.xxFormat:
        hexStyle = "xx"
    if args.psFormat:
        hexStyle = "ps"
    if args.printVersion:
        print(versionInfo)
        sys.exit(0)
    if args.dumpStyle:
        styleDump()

    bufferSize  = args.bufferSize  if args.bufferSize else 0
    startOffset = args.startOffset if args.startOffset else 0
    blockSize   = 16 

    if args.inFile and args.inFile != "-":
        inFile = args.inFile
        with open(inFile,"rb") as f:
            f.seek(startOffset)
            binData = f.read(bufferSize) if bufferSize !=0 else f.read()
            binSize = len(binData)
    else:
        binData = sys.stdin.buffer.read()
        binSize = len(binData)

    if args.makePyScript:
        genPythonScript(binData)

    elif args.makeShellcode:
        genShellcode(binData)

    elif args.reverseDump:
        reverseDump(binData)

    else:
        dHex(binData,startOffset,binSize,blockSize,hexStyle)
