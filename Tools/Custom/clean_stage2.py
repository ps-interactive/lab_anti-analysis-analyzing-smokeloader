import re
import platform
from sys import argv
from hexdump import hexdump
from colorama import Fore as c
from argparse import ArgumentParser
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


def patch_opaques(file_name):
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
    
    patched_file = args.file.replace('\\', '').strip().split('.')[1] + '_patched.bin'

    with open(patched_file, 'wb') as f:
        f.write(data)
    
    validate_opaque_patch(file_name, patched_file, matches)
    


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


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", help="Malware to analyze", metavar='')

    args = parser.parse_args()

    if args.file == None:
        parser.print_help()
        exit(0)
    
    print(c.YELLOW + "[!] Starting analysis on : ", args.file, c.RESET)
    patch_opaques(args.file)
