# DEPS = os.path.join(os.path.dirname(__file__), "deps")

# if DEPS not in sys.path:
#     sys.path.insert(0, DEPS)


# launch_headless_extract.py
# headless_script.py

import ida_idaapi

from ida_db_extract import ida_db_extract_gui

class ida_db_plugmod_t(ida_idaapi.plugmod_t):
    def __del__(self):
        pass
    def run(self, arg):
        ida_db_extract_gui.prompt_and_run_headless()

class ida_db_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "IDA DB Extract Plugin"
    help = "Extracts data from IDA Pro database"
    wanted_name = "IDA DB Extract"
    wanted_hotkey = ""

    def init(self):
        return ida_db_plugmod_t()

def PLUGIN_ENTRY():
    return ida_db_plugin_t()