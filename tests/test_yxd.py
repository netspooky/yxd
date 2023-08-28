import yxd

def yxdTestBasic():
    print("[+] Test: Basic Output ")
    testBuffer1 =  b"\x41"*16
    testBuffer1 += b"\x42"*16
    testBuffer1 += b"\x43"*16
    testBuffer1 += b"\x44"*16
    myYxd  = yxd.yxd(testBuffer1)

def yxdTestYxd():
    print("[+] Test: yxd Color Output ")
    testBuffer1 =  b"\x41"*16
    testBuffer1 += b"\x42"*16
    testBuffer1 += b"\x43"*16
    testBuffer1 += b"\x44"*16
    myYxd = yxd.yxd(testBuffer1, outFormat="yxd")

def yxdTestPs():
    print("[+] Test: ps Output ")
    testBuffer1 =  b"\x41"*16
    testBuffer1 += b"\x42"*16
    testBuffer1 += b"\x43"*16
    testBuffer1 += b"\x44"*16
    myYxd = yxd.yxd(testBuffer1, outFormat="ps")

def yxdTestXx():
    print("[+] Test: xx Output ")
    testBuffer1 =  b"\x41"*16
    testBuffer1 += b"\x42"*16
    testBuffer1 += b"\x43"*16
    testBuffer1 += b"\x44"*16
    myYxd = yxd.yxd(testBuffer1, outFormat="xx")

def yxdTestPythonScript():
    print("[+] Test: Python Script Generator ")
    testBuffer1 =  b"\x41"*16
    testBuffer1 += b"\x42"*16
    testBuffer1 += b"\x43"*16
    testBuffer1 += b"\x44"*16
    myYxd = yxd.yxd(testBuffer1, quiet=True)
    yxd.genPythonScript(myYxd.binData)

def yxdTestShellcode():
    print("[+] Test: Shellcode Loader Generator ")
    testBuffer1 =  b"\x41"*16
    testBuffer1 += b"\x42"*16
    testBuffer1 += b"\x43"*16
    testBuffer1 += b"\x44"*16
    myYxd = yxd.yxd(testBuffer1, quiet=True)
    yxd.genShellcode(myYxd.binData)

def yxdTestReverseDump():
    print("[+] Test: Reverse Hex Dump ")
    testBuffer1 =  b"\x41"*16
    testBuffer1 += b"\x42"*16
    testBuffer1 += b"\x43"*16
    testBuffer1 += b"\x44"*16
    print("    - Intializing")
    myYxd = yxd.yxd(testBuffer1)
    print(f"type: {type(myYxd)}")
    print("    - Getting dump object")
    myYxdOut = myYxd.dump()
    print(f"type: {type(myYxdOut)}")
    print("    - Printing dump object")
    print(myYxdOut)
    print("    - TODO: Doing a reverse hex dump on this object")
    #myYxd.binData = myYxdOut
    #myYxd.reverseDump()

if __name__ == '__main__':
    yxdTestBasic()
    yxdTestYxd()
    yxdTestPs()
    yxdTestXx()
    yxdTestPythonScript()
    yxdTestShellcode()
    yxdTestReverseDump()

