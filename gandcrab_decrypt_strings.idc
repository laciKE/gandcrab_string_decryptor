#include <idc.idc>

static RC4_decrypt(key, key_length, data, length){
    //print(key, length);
    auto i, w, b, K, index, esi, eax, al, edi, edx, dl, ebx, bl, ecx, text;
    auto S = "";
    
    //Key-scheduling algorithm
    for (i=0; i<256; i++){
        S[i] = i;
    }
    w = 0;
    for (i=0; i<256; i++){
        w = (w + ord(S[i]) + ord(key[i % key_length])) % 256;

        b = S[i];
        S[i] = S[w];
        S[w] = b;
    }
   
    //decrypting, xor ciphertext with pseudorandom stream of bytes
    i = w = 0;
    for (index=0; index<length; index++) {
        i = (i+1) % 256;
        w = (w+ord(S[i])) % 256;
        
        b = S[i];
        S[i] = S[w];
        S[w] = b;
     
        K = ord(S[ord(S[i])+ord(S[w]) % 256]) % 256;
        
        data[index] = ord(data[index]) ^ K;
    }

    return data;
}

static wchar2ascii(str) {
    auto i;
    auto ret = "";
    for (i=i; i<strlen(str); i = i + 2) {
        ret = ret + str[i];
    }
    
    return ret;
}

static str2dword(str) {
    auto i, ret;
    ret = 0;
    for (i=3; i>=0; i--) {
        ret = ret*0x100 + ord(str[i]);
    }
    //print("str2dword", str, ret);
    
    return ret;
}

static get_push_reg(addr) {
    // find argument (register name) for string decrypt function
    // in the form of "push %reg"
    
    while (GetMnem(addr) != "push") {
        //Message(" %08lx\t%s\n", addr, GetDisasm(addr));
        addr = FindCode(addr, SEARCH_UP | SEARCH_NEXT);                            
    }
    //Message("push\n %08lx\t%s\n", addr, GetDisasm(addr));
       
    // get register name                            
    return GetOpnd(addr, 0);
}

static get_reg_offset(addr, reg) {
    // find the instruction which sets the value of the pushed register
    // in the form of "lea, %reg, [ebp-offset]"
    do {            
        addr = FindCode(addr, SEARCH_UP | SEARCH_NEXT);                            
    } while ((GetMnem(addr) != "lea") || (GetOpnd(addr,0) != reg));
    //Message("set value\n %08lx\t%s\n", addr, GetDisasm(addr));
    // instruction in the form of "lea %eax, [%ebp-offset]"
    return GetOperandValue(addr,1);
}


static get_start_addr_of_string(addr, offset) {
    // find the address of the instruction which sets the first bytes of reconstructed string
    // in the form of "mov [ebp-offset], imm"
    do {
        addr = FindCode(addr, SEARCH_UP | SEARCH_NEXT);
    }
    while ((GetMnem(addr) != "mov") || (GetOpType(addr,1) != o_imm) || (GetOperandValue(addr,0) != offset));

    return addr;
}

static get_max_offset(addr1, addr2) {
    // find the max offset (aka end of the reconstructed string) across the "mov [ebp-offset], imm" instructions
    auto addr, offset, max = -0x1fffffff;
    for (addr = addr1; addr < addr2; addr = FindCode(addr, SEARCH_DOWN | SEARCH_NEXT)) {
        if ((GetMnem(addr) == "mov") && (GetOpType(addr,1) == o_imm)) {
            offset = GetOperandValue(addr,0);
            if (offset > max) {
                max = offset;
            }
        }
    }
    return max;
}

static get_string_argument(ref) {
    auto addr, reg, ebp_offset, ebp_max_offset, arglength, argument;
    // get register name from the instruction "push %reg"                            
    reg = get_push_reg(ref);
            
    // get ebp offset stored in register by instruction "lea, %reg, [ebp-offset]"
    // aka start of the reconstructed string argument
    ebp_offset = get_reg_offset(ref, reg);

    // find the instruction which sets the first bytes of reconstructed string
    addr = get_start_addr_of_string(ref, ebp_offset);
            
    // find the max ebp offset, aka end of the reconstructed string argument
    ebp_max_offset = get_max_offset(addr, ref);
    arglength = ebp_max_offset - ebp_offset;
    argument = strfill('\x00', arglength);
            
    //Message(" ebp_offset=%x, ebp_max_offset=%x, arglength=%x, addr=%08lx\n",ebp_offset, ebp_max_offset, arglength, addr);
    // reconstruct string argument from instruction like "mov [ebp-offset], value"
    auto offset, value;
    for (addr; addr < ref; addr=FindCode(addr,SEARCH_DOWN|SEARCH_NEXT)) {
        // instruction like "mov [ebp-offset], value"
        if ((GetMnem(addr) == "mov") && (GetOpType(addr,1) == o_imm)) {
            offset = GetOperandValue(addr,0);
            // set value for desired string argument starting at [ebp-ebp_offset]
            if (offset-ebp_offset >= 0) {
                value = GetOperandValue(addr,1);
                //Message(" %08lx\t[%d] = %08x\n", addr, offset-ebp_offset, value);
                //Message(" %08lx\t%s\n", addr, GetDisasm(addr));
          
                //convert dword value to bytes in string
                auto i;
                for (i=0; i<4; i++) {
                    argument[offset-ebp_offset+i] = value & 0xFF;
                    value = value>>8;
                }                        
            }
        }
    }
    //Message(" %08lx\targument\n", ref);
    //print(argument);
    
    return argument;
}

static count_xrefs(addr) {
    auto ref, count;
    count = 0;
    ref = RfirstB(addr);
    while (ref!=BADADDR) {
        count = count + 1;
        ref = RnextB(addr,ref);
    }
    
    //Message("%08x: %d, %x\n", addr, count,GetFunctionAttr(addr,FUNCATTR_FRSIZE));
    return count;
}

static find_decrypt_function() {
    // find the address of the string decryption function with following conditions:
    //   it is short (up to 0x25 bytes)
    //   it is heavily used (at least 100 xrefs)
    //   it contains exactly one call instruction (for calling RC4 decryption routine)
    //   it contains exactly 5 push instructions (one push ebp from prologue and 4 arguments for RC4)
    auto func_start, func_end, found;
    found = 0;
    func_start = NextFunction(0);
    while ((func_start!=BADADDR) && (found == 0)) {
        func_start = NextFunction(func_start);
        func_end = FindFuncEnd(func_start);
        if (func_end-func_start < 0x25) {
            auto  addr, push_count, call_count;
            push_count = 0;
            call_count = 0;
            addr = func_start;
            while (addr < func_end) {
                if (GetMnem(addr) == "push") push_count = push_count + 1;
                if (GetMnem(addr) == "call") call_count = call_count + 1;
                addr = FindCode(addr, SEARCH_DOWN | SEARCH_NEXT);                            
            }
        
            if ((push_count == 5) && (call_count == 1) && (count_xrefs(func_start) > 100))  {
                found = 1;
            }
        }
        //Message("%08x: %08x, %d --> %d\n", func_start, func_end, count_xrefs(func_start), found);               
    }
    
    return func_start;
}


static main() {
    Message("\n=====GandCrab String Decryptor=====\n\n");
    auto ea, ref;
    // string decrypt function
    //ea = 0x407563;
    ea = find_decrypt_function();
    // get first xref to calling decrypt function
    ref = RfirstB(ea);
    while (ref!=BADADDR) {
    //ref = 0x10006866;
        Message("%08lx: xref to decrypt function %08lx \n", ref, ea);
        // find xrefs to calling decrypt function
        if ((XrefType() == fl_CN) || (XrefType() == fl_CF)) {
            // reconstructs string argument
            auto argument = get_string_argument(ref);
            
            // parse parameters from string argument
            auto key_length = 0x10;
            auto key = substr(argument,0,key_length);
            auto data = substr(argument,key_length+8,-1);
            auto length = str2dword(substr(argument,key_length,key_length+4)) ^ str2dword(substr(argument,key_length+4,key_length+8));
            //print(length);
            // if the strings is too long, there may be an error, or it can be long binary data
            if (length < 0x10000) {
                auto text = RC4_decrypt(key, key_length, data, length);
                auto plaintext;
                // simple check for widechar string
                if (text[1] == '\x00') {
                    plaintext = wchar2ascii(text);
                } else {
                    plaintext = text;
                }
                
                // prints decrypted string to output windows
                Message("\"%s\" (length: 0x%x)\n\n", plaintext, strlen(plaintext));  ;              
                // puts comment at the call of the decryption function
                MakeComm(ref, plaintext);
            }
        }
        ref = RnextB(ea,ref);
    }
    
    //auto ret = RC4_decrypt("OJ\xABkMp\x10\x9B\xA4\xCF\x041\xD0\x7Fe\xDE", 0x10, "\xD8#(\xDALF\x90\r\xC3\xAC\xFA\x0F\xBE\xBA\xB3k\xD5\xE7\xB5\xF0\x06""7", 0x16);
    //msg("\"%s\" (wchar length: 0x%x)\n", wchar2ascii(ret), strlen(ret));
}
