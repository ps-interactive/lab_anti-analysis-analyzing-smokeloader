import re
from sys import argv
from hexdump import hexdump
from colorama import Fore as c
from argparse import ArgumentParser

"""
References / Additional Resources:

- https://n1ght-w0lf.github.io/malware%20analysis/smokeloader/#anti-debugging                               (Most detailed in SmokeLoader technqiues)

- https://research.openanalysis.net/smoke/smokeloader/loader/config/yara/triage/2022/08/25/smokeloader.html  (Brings all resources together)

- https://github.com/myrtus0x0/smoke_conf_extract

- https://gist.github.com/alexander-hanel/faff87d25f4b2896241c8f835fa1a321

- https://app.any.run/tasks/679d3672-8a8a-43db-8d14-75255d6c6c11/

- https://app.any.run/tasks/08334f06-faa3-41f9-a5b9-4dffb688101e/

"""

def hash_djb2(s):
    """
    This function is from : https://research.openanalysis.net/smoke/smokeloader/loader/config/yara/triage/2022/08/25/smokeloader.html
    """                                                                                                                   
    hash = 5381
    for x in s:
        hash = (( hash << 5) + hash) + x
    return hash & 0xFFFFFFFF

def rc4crypt(data, key):
    """
    This function is from : https://research.openanalysis.net/smoke/smokeloader/loader/config/yara/triage/2022/08/25/smokeloader.html
    """
    #If the input is a string convert to byte arrays
    if type(data) == str:
        data = data.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + key[i % len(key)]) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for c in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(c ^ box[(box[x] + box[y]) % 256])
    return bytes(out)

def decrypt_function(pe, offset, size):
    """

    This function is located at 0x00401294 in our first sample
    It gets call by a function at 0x0040136A, which takes the args (offset, size)
    - Place breakpoint at 0x00402DC2 (to get args for first decrypt)
        - (00402eeb , 000000f0)

    XOR Key identified as : 0xA6
    """
    base_addr = 0x00400000
    chunk_offset = offset - base_addr
    print(hex(chunk_offset))
    print(hex(len(pe)))

    encrypted_chunk = pe[chunk_offset: chunk_offset + size]
    decrypted_chunk = bytearray()
    print("[!] Decrypting function body... ")
    hexdump(encrypted_chunk)

    index = 0

    while index < size:
        decrypted_chunk += (encrypted_chunk[index] ^ 0xA6).to_bytes()
        # Start of buffer
        index += 1
    
    print("[!] Decrypted function body!")
    hexdump(decrypted_chunk)

    # Patch PE
    pe = pe.replace(encrypted_chunk, decrypted_chunk)

    return pe


def patch_PEB_checks(data):
    """
    
    Anti-Analysis checks performed by the shellcode to verify if its being debugger
    - PEB->BeingDebugged
    - PEB->NTGlobalFlag
        https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-peb-beingdebugged-flag
    
    """

    first_round = patch_PEB_debugged(data)

    second_round = patch_PEB_NtGlobalFlag(first_round)

    return second_round


def patch_PEB_NtGlobalFlag(data):
    """
    This flag is set when a process is spawned by a debugger
    """

    PEB_NTGlobalFlag_offset = rb'\x0F\xB6\x46\x68'
    r = re.compile(PEB_NTGlobalFlag_offset)
    matches = r.finditer(data)

    for match in matches:
        print('Found!')
        print(match.start(), match.end())
        hexdump(data[match.start(): match.end()+2])
        data[match.end()-1] = 0x70
        hexdump(data[match.start(): match.end()+2])
    
    return data

def patch_PEB_debugged(data):
    """
    """
    copy_PEB_debugged_addr = rb'\xB6\x40\x02\xEB\x02'
    not_debugged = rb'\xB6\x40\x02\xEb\x00'

    r = re.compile(copy_PEB_debugged_addr)

    matches = r.finditer(data)
    print('PEB')
    for match in matches:
        print('Found!')
        print(match.start(), match.end())
        hexdump(data[match.start(): match.end()+2])
        data[match.end()-3] = 0x00
        hexdump(data[match.start(): match.end()+2])

    return data

def patch_je_jne_opaque(data):
    """
    Control Flow Obfuscation through je/jnz opcodes
    - Both jmp addresses resolve to same address, but they confuse the dis
    """
    patched = b''
    je_jne_opcodes = b'\x74.\x75.'
    jne_je_opcodes = b'\x75.\x74'

    first = re.compile(je_jne_opcodes)
    second = re.compile(jne_je_opcodes)

    for sig in (first, second):
        matches = sig.finditer(data)

        for match in matches:
            print(c.RED, "Patching:")
            hexdump(data[match.start() - 4 : match.end() + 4])
            print(data[match.start()])
            data[match.start()] = 0xEB
            data[match.start()+2] = 0x90
            data[match.start()+3] = 0x90
            print(c.GREEN, "New Value:", c.RESET)
            hexdump(data[match.start() - 4 : match.end() + 4])

    #final = patch_PEB_checks(data)
    print("Only patching je/jnz!")
    return data

if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument("-f", "--file", help="Malware to analyze")
    parser.add_argument('-conf', help="Extract configuration")
    parser.add_argument('-ck', help="Configuration RC4 key from sample")
    parser.add_argument('--patch', help='Remove obfuscation techniques and patch binary')
    parser.add_argument('-e', '--extract', help='Extract all embedded payloads from sample')

    if len(argv) < 2:
        print("No target file!")
        exit()
    
    print("Loading : ", argv[1])
    
    with open(argv[1], 'rb') as f:
        data = bytearray(f.read())
    
    cleaned_pe = patch_je_jne_opaque(data)

    file_name = argv[1].replace('\\', '').strip().split('.')[1] + '_patched.bin'

    print("Creating new file: ", file_name)
    with open(file_name, 'wb') as f:
        f.write(cleaned_pe)