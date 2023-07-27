import re
import struct
import platform
from sys import argv
from hexdump import hexdump
from colorama import Fore as c
from argparse import ArgumentParser, BooleanOptionalAction
from analyze_pe import Rizin


# Windows logging console
if platform.system() == 'Windows':
    from colorama import just_fix_windows_console
    just_fix_windows_console()


def find_opaque_predicates(data):
    """
    Control Flow Obfuscation through je/jnz opcodes
    - Both jmp addresses resolve to same address, but they confuse the disasm
    """
    je_jne_opcodes = re.compile(b'\x74.\x75.')
    jne_je_opcodes = re.compile(b'\x75.\x74')
    # Store matches for comparison and patching later
    found = []

    # Find matches in binary
    for sig in (je_jne_opcodes, jne_je_opcodes):
        matches = sig.finditer(data)
        for match in matches:
            found.append(match)
    return found


def patch_opaques(file_name, output=""):
    """
    Use offsets to patch in-memory copy and write new file
    """
    with open(file_name, 'rb') as f:
        data = bytearray(f.read())
    

    matches = find_opaque_predicates(data)

    if len(matches) > 0:
        for match in matches:
            data[match.start()] = 0xEB
            data[match.start()+2] = 0x90
            data[match.start()+3] = 0x90
    if output:
        patched_file = output
    else:
        patched_file = file_name.replace('\\', '').strip().split('.')[1] + '_no_opaques.bin'

    with open(patched_file, 'wb') as f:
        f.write(data)
    
    validate_opaque_patch(file_name, patched_file, matches)

    return patched_file
    

def validate_opaque_patch(original, patched, mods):
    """
    Display to user what bytes were patched, confirming our new file contains different instructions
    """
    orig_rz = Rizin(original)
    patched_rz = Rizin(patched)
    total_patches = len(mods)
    success = 0

    for mod in mods:
        # Display opaque predicate
        print(c.RED + f'[!] Identified opaque predicate!')
        orig_rz.disasm(mod.start())
        old_bytes = orig_rz.get_chunk(mod.start(), 0x2)
        print('-' * 40)
        
        # Display new patched value
        print(c.GREEN + f'[+] Patched value: ')
        patched_rz.disasm(mod.start(), chunk_size=3)
        new_bytes = patched_rz.get_chunk(mod.start(), 0x2)
        
        # Validate we corrected all predicates
        if new_bytes != old_bytes:
            success += 1
        print(c.BLUE + '-' * 64, c.RESET)
        
    if success == total_patches:
        print(c.GREEN + f'[+] Successfully patched ({success}/{total_patches}) opaque predicates\n\n\tPatched file: "{patched}"\n', c.RESET)

def patch_xor_calls(rz: Rizin):
    """
    Remove all calls to XOR function
     - when debugging these will re-encrypt our hard work!
     - these additional sections where found after decrypting the new
       function bodies and starting debugging
    """
    with open(rz.file_name, 'rb') as f:
        payload = f.read()

    clean_payload = b''

    additional_sections_to_nop = [
        0x00401316,
        0x00401549,

    ]

    for section in sections_to_nop.values():
        if payload.find(section):
            print('Find encrypted call! Replacing with NOPs..')
            payload = payload.replace(section, b'\x90\x90\x90\x90\x90')
    
    for section in sections_to_nop.values():
        if payload.find(section) > 1:
            still_there = payload.find(section)
            hexdump(payload[still_there:still_there+10])
            print('Patch didnt work! ', payload.find(section))

    with open('deflated_no_encrypt.bin', 'wb') as f:
        f.write(payload)
        
def decrypt_body(chunk, key):
    
    decrypted_func = b''
    
    for _byte in chunk:
        xored_byte = _byte ^ key
        decrypted_func += struct.pack('B', xored_byte)
    
    return decrypted_func

def decrypt_sections(rz: Rizin, encryped_functions: dict, blob):
    # Decrypt remaining function (second round)
    for offset, function in encryped_functions.items():
        print(c.BLUE + f"[+] Decrypting function at : [{hex(function['rva'])}]", c.RESET)
        enc = rz.get_chunk(function['rva'], function['size'])
        dec = decrypt_body(enc, function['key'])
        blob = blob.replace(enc, dec)
    
    return blob

def decrypt_functions(file_name):
    """
    The majority of the functions for Stage2 are encrypted and we must decrypt, before continuing
    - The offset to calculate the RVA is store in EAX
    - The size of the function to decrypt is stored in ECX
    - The xor_key to decrypt the functio is stored in EDX
    """
    rz = Rizin(file_name)
    with open(file_name, 'rb') as f:
        raw_bin = f.read()
    
    base_address = 0x00400000
    encryped_functions = {
        0x004012AB: {'rva': base_address + 0x12B0,
                     'size': 0x6B,
                     'key': 0x1c},
        0x004014AA: {'rva': base_address + 0x14AF,
                     'size': 0x9F,
                     'key': 0x9B},
        0x0040159F: {'rva': base_address + 0x15A4,
                     'size': 0x387,
                     'key': 0x83},
        0x00401981: {'rva': base_address + 0x1986,
                     'size': 0x6D,
                     'key': 0x0C5},
        0x00401A41: {'rva': base_address + 0x1A46,
                     'size': 0x1CE,
                     'key': 0x55},
        0x00401C58: {'rva': base_address + 0x1C5D,
                     'size': 0x66,
                     'key': 0x32},
        0x00401D0D: {'rva': base_address + 0x1D12,
                     'size': 0x0DD,
                     'key': 0x9B},
        0x00401E41: {'rva': base_address + 0x1E46,
                     'size': 0x0ED,
                     'key': 0x0BE},
        0x00401F7E: {'rva': base_address + 0x1F83,
                     'size': 0x95,
                     'key': 0x0B},
        0x00402064: {'rva': base_address + 0x2069,
                     'size': 0x8A,
                     'key': 0x8D},
        0x0040213E: {'rva': base_address + 0x2143,
                     'size': 0x238,
                     'key': 0x0AD},
        0x004023D0: {'rva': base_address + 0x23D5,
                     'size': 0x9F,
                     'key': 0x0B3},
        0x004024C4: {'rva': base_address + 0x24C9,
                     'size': 0x29C,
                     'key': 0x8A},
        0x004027B5: {'rva': base_address + 0x27BA,
                     'size': 0x1A4,
                     'key': 0x52},
        0x004029A7: {'rva': base_address + 0x29AC,
                     'size': 0x64,
                     'key': 0x48},
        0x00402A62: {'rva': base_address + 0x2A67,
                     'size': 0x0A6,
                     'key': 0x47},
        0x00402B58: {'rva': base_address + 0x2B5D,
                     'size': 0x5E,
                     'key': 0x56},
        0x00402BFA: {'rva': base_address + 0x2BFF,
                     'size': 0x7D,
                     'key': 0x51}
    }

    # These were identified after initial decryption (first round)
    new_decrypt_function = {
        0x00402CC5: {'rva': base_address + 0x2CCA,
                     'size': 0x0B0,
                     'key': 0x89},
        0x00401364: {'rva': base_address + 0x1369,
                     'size': 0x0F4,
                     'key': 0x21}   # Might be wrong
    }

    third_round_functions = {
        0x00402DBD: {'rva': base_address + 0x2DC2,
                     'size': 0x0B1,
                     'key': 0x0A1}
    }

    fourth_round_functions = {
        0x00402EAB: {'rva': base_address + 0x2EB0,
                     'size': 0x0CB,
                     'key': 0x0C}
    }
    """
    # Decrypt all functions (first round)
    for offset, func in encryped_functions.items():
        
        # Get call to xor_function
        # Validate we are getting call inst
        #rz.disasm(func['rva'] - 0x5, 0x1, rva=True)
        call_xor = rz.get_chunk(func['rva'] - 0x5, 0x5)
        print(c.GREEN + f"[+] Decrypting function at : [{hex(func['rva'])}]", c.RESET)
        
        # Get encrypted function body and decrypt with key
        encrypted = rz.get_chunk(func['rva'], func['size'])
        decrypted = decrypt_body(encrypted, func['key'])
        
        # Remove call to xor_function so we don't re-encrypt while debugging
        if call_xor:
            print(c.GREEN + '\t - patching call to xor_function with NOPs', c.RESET)
            raw_bin = raw_bin.replace(call_xor, b'\x90\x90\x90\x90\x90')
        
        # Patch encrypted function
        raw_bin = raw_bin.replace(encrypted, decrypted)
    """
    # Decrypt all functions (first round)
    raw_bin = decrypt_sections(rz, encryped_functions, raw_bin)
    
    # Second round
    raw_bin = decrypt_sections(rz, new_decrypt_function, raw_bin)
    
    # Third round
    raw_bin = decrypt_sections(rz, third_round_functions, raw_bin)

    # Fourth round
    raw_bin = decrypt_sections(rz, fourth_round_functions, raw_bin)
    
    # Total functions patched
    total = len(encryped_functions.keys()) + len(new_decrypt_function.keys()) + len(third_round_functions.keys()) + len(fourth_round_functions.keys())
    print(c.GREEN + f'[+] Successfully decrypted ({total}) functions! ', c.RESET)
    with open('decrypted_stage2.bin', 'wb') as f:
        f.write(raw_bin)
    

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", help="Malware to analyze", metavar='', required=False)
    parser.add_argument('-op', "--opaques", action='store_true', help="Patch opaque predicates")
    parser.add_argument('-enc', '--encrypted', action='store_true', help='Patch encrypted functions')

    args = parser.parse_args()

    if args.file == None:
        parser.print_help()
        exit(0)
    print(c.YELLOW + "[!] Starting analysis on : ", args.file, c.RESET)
    if args.opaques:    
        patch_opaques(args.file)
    elif args.encrypted:
        decrypt_functions(args.file)
        patch_opaques('decrypted_stage2.bin', output='decrypted_stage2_no_opaques.bin')
    else:
        print(args.file, args.encrypted)
