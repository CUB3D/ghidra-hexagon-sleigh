#@author CUB3D
#@category Qualcomm
#@runtime Jython

# A script to annotate the CLADE config TLVs, which can be found by searching for the string "invalid QURTK"

START_ADDR = toAddr(0xc0000048)

pos = START_ADDR

while True:
    clearListing(pos, pos.add(4))
    tlv_start_pos = pos
    size = getShort(pos)
    createWord(pos)
    pos = pos.add(2)
    tag = getShort(pos)
    createWord(pos)
    pos = pos.add(2)
    if tag == 0x03: # no clue
            clearListing(pos, pos.add(12))
            createDWord(pos)
            createDWord(pos.add(4))
            createDWord(pos.add(8))
    elif tag == 0x04: # CLADE dicts
            clearListing(pos, pos.add(12))
            createDWord(pos) # addr
            createDWord(pos.add(4)) # mmio register?
            createDWord(pos.add(8)) # size
    elif tag == 0x05: # CLADE base??
            clearListing(pos, pos.add(20))
            createDWord(pos)
            createDWord(pos.add(4))
            createDWord(pos.add(8))
            createDWord(pos.add(12))
            createDWord(pos.add(16))
    elif tag == 0x10: # Process name?
            clearListing(pos, pos.add(20))
            s = createAsciiString(pos)
    elif tag == 0x11: # CLADE related?
            clearListing(pos, pos.add(16))
            createDWord(pos)
            createDWord(pos.add(4))
            createDWord(pos.add(8))
            createDWord(pos.add(12))
    elif tag == 0x12: # Idk
            clearListing(pos, pos.add(12))
            createDWord(pos)
            createDWord(pos.add(4))
            createDWord(pos.add(8))
    elif tag == 0x13: # CLADE exc_hi
            clearListing(pos, pos.add(4))
            createDWord(pos)
    elif (size, tag) == (0x00, 0x00): # End
        break
    pos = tlv_start_pos.add(size)
