// (c) 2020 Ladislav Baco
// Twitter: @ladislav_b
// https://github.com/laciKE/snatch_string_decryptor
//
// This IDC script is inspired by LIFARS IDA Python script:
// https://github.com/Lifars/IDA-scripts/blob/master/snatch_decrypt_strings.py
//
// This code is licensed under MIT license (see LICENSE for details)

#include <idc.idc>


// Base64 decoding inspiraed by 
// https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/

static b64_decode(in) {
    auto b64invs = "\x3e\xff\xff\xff\x3f\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\xff\xff\xff\xff\xff\xff\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\xff\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33";
    auto i, w, tmp;
    auto out = "";
    for (i = 0, w = 0; i < strlen(in); i = i+4, w = w+3) {
        tmp = ord(b64invs[ord(in[i])-43]);
        tmp = (tmp << 6) | ord(b64invs[ord(in[i+1])-43]);
        tmp = in[i+2]=="=" ? tmp << 6 : (tmp << 6) | ord(b64invs[ord(in[i+2])-43]);
        tmp = in[i+3]=="=" ? tmp << 6 : (tmp << 6) | ord(b64invs[ord(in[i+3])-43]);
        
        out[w] = char((tmp >> 16) & 0xFF);
        if (in[i+2] != "=") {
            out[w+1] = char((tmp >> 8) & 0xFF);
        }
        if (in[i+3] != "="){
            out[w+2] = char(tmp & 0xFF);
        }
    }
    
    return out;
}

static get_string_address(addr) {
    // find instruction "lea reg, str_addr" and get str_addr
    auto str_addr;
    do {
        addr = find_code(addr, SEARCH_UP | SEARCH_NEXT);
    }
    while ((print_insn_mnem(addr) != "lea") || (get_operand_type(addr,0) != o_reg) || (get_operand_type(addr,1) != o_mem));
    str_addr = get_operand_value(addr,1);
    
    return str_addr;
}


static get_string_length(addr) {
    // find instruction "mov [rsp+offset], imm" and get imm 
    auto str_length;
    do {
        addr = find_code(addr, SEARCH_UP | SEARCH_NEXT);
    }
    while ((print_insn_mnem(addr) != "mov") || (get_operand_type(addr,0) != o_displ) || (get_operand_type(addr,1) != o_imm));
    str_length = get_operand_value(addr,1);
    
    return str_length;
}

static decrypt_string(str, key) {
    auto cipher, plain, key_length, i;
    cipher = b64_decode(str);
    plain = "";
    key_length = strlen(key);
    for (i = 0; i < strlen(cipher); i++) {
        plain[i] = char(ord(cipher[i]) ^ ord(key[i % key_length]));
    }
    
    return b64_decode(plain); 
}

static main() {
    auto arch,  ea, key_addr, key_length, key;
    auto get_word, ref;

    arch = (get_inf_attr(INF_LFLAGS) & LFLG_64BIT) ? 64 : 32;
    if (arch == 64) {
        get_word = get_qword;
    } else {
        get_word = get_wide_dword;
    }

    // string decrypt function
    ea = get_name_ea_simple("main.decodeString");
    // address of xor key
    key_addr = get_name_ea_simple("main.encoderKey");
    // length of xor key
    key_length = get_word(key_addr + arch/8);
    //eex xor key value
    key = get_bytes(get_word(key_addr), key_length, 0);

    Message("XOR Encoder Key: %s\n", key);

    // get first xref to calling decrypt function
    ref = RfirstB(ea);
    while (ref!=BADADDR) {
        //Message("0x%x: xref to decrypt function %08lx \n", ref, ea);
        // find xrefs to calling decrypt function (Call Near and Call Far)
        if ((XrefType() == fl_CN) || (XrefType() == fl_CF)) {
            // get obfuscated string
            auto str_addr = get_string_address(ref);
            auto str_length = get_string_length(ref);
            auto encrypted_str = get_bytes(str_addr, str_length, 0);
            auto decrypted_str = decrypt_string(encrypted_str, key);
            Message("0x%x -> 0x%x[0x%x] = \"%s\"\n", ref, str_addr, str_length, decrypted_str);
             
            // puts comment at the call of the decryption function
            set_cmt(ref, decrypted_str, 0);
          }
      
        ref = RnextB(ea,ref);
    }
}
