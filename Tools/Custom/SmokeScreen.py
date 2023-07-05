"""
"""

from colorama import Fore as c
from dbg_help import inject_hook, get_pid
from analyze_pe import Rizin
from win32mem import scan_memory, get_memory_range
import pyfiglet
import cmd
banner = c.GREEN + pyfiglet.figlet_format("Smoke", font='thick')


class SmokePrompt(cmd.Cmd):
    intro = banner + "\nWelcome.. Type help or ? to list commands.\n"
    prompt = c.BLUE + "(" + c.WHITE + "SmokeScreen" + c.BLUE + ")=> " + c.RESET
    file = None
    
    def do_get_pid(self, arg):
        """
        Get process id (PID) for process name
        """
        args = arg.split()

        if len(args) < 1:
            print(c.RED + "[-] Must supply valid process name (get_pid stage1.exe)", c.RESET)
        else:
            print(c.GREEN + 'PID: ', get_pid(args[0]))
    
    def do_show_memory(self, arg):
        "Display pages of interest in Remote Process"

        args = arg.split()
        try:
            pid = int(args[0])
            scan_memory(pid, get_memory_range())
        except ValueError:
            print(c.RED + "[-] Bad PID given.. Expected: (show_memory <pid>)")
            return
                 
    def do_dump_memory(self, arg):
        pass

    def do_inject_hook(self, arg):
        args = arg.split()
        if len(args) < 1:
            print(c.RED + "[-] Must supply either PID or process name (inject_hook stage1.exe)", c.RESET)
        else:
            inject_hook(args[0])

    def do_defobufscate(self, arg):
        pass
    
    def upload_patch(self, arg):
        pass


if __name__ == "__main__":
    s = SmokePrompt()
    s.cmdloop()
