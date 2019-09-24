import sys, time
print "sex"
xorFunctions = []

def AnalyzeMethod(start):
    end = GetFunctionAttr(start,FUNCATTR_END)
    fnPtr = start
    isXor = 0 
    while fnPtr and fnPtr < end and end !=BADADDR:
        opcode = GetMnem(fnPtr)
        operand0,operand1 = GetOpnd(fnPtr,0),GetOpnd(fnPtr,1)
        #print "Opcode %s %s %s" % (opcode,operand0,operand1) 
        
        if opcode == 'movsx':
            tmpFn = FindCode(fnPtr,SEARCH_DOWN | SEARCH_NEXT)
            tmpOpcode = GetMnem(tmpFn)
            if tmpOpcode == 'xor':
                print "its Xor %02x" % tmpFn
                isXor = 1
                xorFunctions.append(start)
        elif opcode == 'dec':
                tmpFn = FindCode(fnPtr,SEARCH_DOWN | SEARCH_NEXT)
                tmpOpcode = GetMnem(tmpFn)
                if tmpOpcode == 'or':
                    tmp2fn = FindCode(tmpFn,SEARCH_DOWN | SEARCH_NEXT) 
                    tmp2Opcode = GetMnem(tmp2fn)
                    if tmp2Opcode == 'inc':
                         print "its Xor2 %02x" % tmp2fn
                         isXor = 1
                         xorFunctions.append(start)
                   
        fnPtr = FindCode(fnPtr,SEARCH_DOWN | SEARCH_NEXT) 
    return isXor


def GetKeyCounter(adres):
     fnPtr = adres
     isCountered = 0
     for a in xrange(5):
        fnPtr = FindCode(fnPtr,SEARCH_UP | SEARCH_NEXT)
        opcode = GetMnem(fnPtr) 
        if opcode == 'lea':
            isCountered+=1
        elif opcode == 'sub':
             isCountered+=1
        elif opcode == 'mov':
             isCountered+=1

     if isCountered == 3:
         return isCountered

     isCountered = 0
     for a in xrange(4):
        fnPtr = FindCode(fnPtr,SEARCH_UP | SEARCH_NEXT)
        opcode = GetMnem(fnPtr)
        if opcode == 'lea':
            isCountered+=1
        elif opcode == 'push':
             isCountered+=1
     return isCountered


def GetXorKey(base,xtype):
    fnPtr = base
    opcode = GetMnem(fnPtr)
    if xtype == 3:
        operand0,operand1 = GetOpnd(fnPtr,0),GetOpnd(fnPtr,1)
        if opcode == 'mov':
            key = operand1.replace("h","")
            return int(key,16)
    return -1        #print "%s %s %s -base : %02x" % (opcode,operand0,str(int(key,16)),base)

def GetXorLen(base,fnPtr,xtype):
    end = GetFunctionAttr(fnPtr,FUNCATTR_END)   
    strlen = 0
    while fnPtr and fnPtr < end and end !=BADADDR:
         tmpOpcode = GetMnem(fnPtr)
         if tmpOpcode == 'cmp':
             tmpPtr = FindCode(fnPtr,SEARCH_DOWN | SEARCH_NEXT)
             tmp2Opcode = GetMnem(tmpPtr)
             if tmp2Opcode == 'jl':
                 strlen = get_operand_value(fnPtr,1)       
         fnPtr = FindCode(fnPtr,SEARCH_DOWN | SEARCH_NEXT)
    return strlen

#def CalcXoref(base,xptr,xtype):
        
def GetXorBuffer(base,xptr,xtype):
    fnPtr = xptr
    if xtype == 2:
        return "not implemented"
        for xi in xrange(2):
            fnPtr = FindCode(fnPtr,SEARCH_UP | SEARCH_NEXT)
            opcode = GetMnem(fnPtr)
            operand0,operand1 = GetOpnd(fnPtr,0),GetOpnd(fnPtr,1)
            if opcode == 'push':
                return "not implemented"
                #print "xor buffer : %s" % operand0.replace("h","")
    elif xtype == 3:
        for xi in xrange(6):
            fnPtr = FindCode(fnPtr,SEARCH_UP | SEARCH_NEXT)
            opcode = GetMnem(fnPtr)
            operand0,operand1 = GetOpnd(fnPtr,0),GetOpnd(fnPtr,1)
            if opcode == 'mov':
                break
        opcode = GetMnem(fnPtr)
        if opcode == 'mov':
            operand0,operand1 = GetOpnd(fnPtr,0),get_operand_value(fnPtr,1)
            buffer_ptr = operand1
            #buffer_ptr = str(operand1[11:]) ## string buffer ptr   
            #if len(buffer_ptr) > 5:
            if buffer_ptr !=BADADDR and buffer_ptr !=00:
                encstr = buffer_ptr
                #encstr = int(buffer_ptr,16)
                validate = ord(get_bytes(encstr,1))
                if validate == 255: ## bozuk decrypt ettik reiz
                    
                    return "bozuk cikti riza baba"
                bytes_str = get_bytes(encstr,100)
                xorkey = GetXorKey(base,3) # xor tip mov
                slen = GetXorLen(base,base,3) # 3. tip uzunluk
                decrypted = xBreak(bytes_str,slen,xorkey)
                return decrypted
                #print "last operand : %s value %s xorkey %d - dec str : %s" % (opcode,buffer_ptr,xorkey,decrypted)
    return ""            
def xBreak(strin,slens,skey):
    output = []
    slen = 0
    if slens != 0:
      slen = slens
    else: 
      slen = len(strin)
    okey = skey
    for i in xrange(slen):
        output.append((okey ^ ord(strin[i])))
        okey = (okey + 1) % 256
    return ''.join(str(chr(e)) for e in output)

def xRefAnalyzer():
    for adres in xorFunctions:
        xrefs = XrefsTo(adres,0)
        for xrefptr in xrefs:
            #print "xref adres xor : %02x" % xrefptr.frm
            xorChance = GetKeyCounter(xrefptr.frm)
            if xorChance == 3 or xorChance == 2:
                buff = GetXorBuffer(adres,xrefptr.frm,xorChance)
                set_cmt(xrefptr.frm,"Decrypt : "+ buff,0)
                print "definetely xor : %02x type : %d - %s" % (xrefptr.frm,xorChance,buff)


        
def MainScan():
    print "Main Scanner"
    fnPtr = NextFunction(0)
    while fnPtr !=BADADDR:
        #print 'Function PTR [%02x]' % fnPtr
        fnPtr = NextFunction(fnPtr)
        AnalyzeMethod(fnPtr)

if __name__ == '__main__':
    print "LSXor Breaker Initialized"
    #if AnalyzeMethod(0x1000CA80) == 1:
    #    print "Xor Found"
    MainScan()
    xRefAnalyzer()
   
