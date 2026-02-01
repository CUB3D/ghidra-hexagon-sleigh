#@author CUB3D
#@category Qualcomm
#@runtime Jython

START_ADDR = toAddr(0xc0000040)

pos = START_ADDR

while True:
    clearListing(pos, pos.add(4))
    first = getShort(pos)
    createWord(pos)
    pos = pos.add(2)
    second = getShort(pos)
    createWord(pos)
    pos = pos.add(2)
    if (first, second) == (0x10, 0x03): # no clue
            clearListing(pos, pos.add(12))
            createDWord(pos)
            createDWord(pos.add(4))
            createDWord(pos.add(8))
            pos = pos.add(12)
    elif (first, second) == (0x10, 0x04): # CLADE dicts
            clearListing(pos, pos.add(12))
            createDWord(pos) # addr
            createDWord(pos.add(4)) # mmio register?
            createDWord(pos.add(8)) # size
            pos = pos.add(12)
    elif (first, second) == (0x18, 0x05): # Idk
            clearListing(pos, pos.add(20))
            createDWord(pos)
            createDWord(pos.add(4))
            createDWord(pos.add(8))
            createDWord(pos.add(12))
            createDWord(pos.add(16))
            pos = pos.add(20)
    elif (first, second) == (0x14, 0x10): # Process name?
            clearListing(pos, pos.add(20))
            s = createAsciiString(pos)
            pos = pos.add(s.getLength()+3)
    elif (first, second) == (0x14, 0x11): # CLADE related?
            clearListing(pos, pos.add(16))
            createDWord(pos)
            createDWord(pos.add(4))
            createDWord(pos.add(8))
            createDWord(pos.add(12))
            pos = pos.add(16)
    elif (first, second) == (0x10, 0x12): # Idk
            clearListing(pos, pos.add(12))
            createDWord(pos)
            createDWord(pos.add(4))
            createDWord(pos.add(8))
            pos = pos.add(12)
    elif (first, second) == (0x08, 0x13): # CLADE exc_hi
            clearListing(pos, pos.add(4))
            createDWord(pos)
            pos = pos.add(4)
    elif (first, second) == (0x00, 0x00): # End
        break