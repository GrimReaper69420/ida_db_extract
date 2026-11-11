# Ida Imports
import ida_auto
import ida_pro
import idc

# FFor Logging and Stuff
import datetime
import json

# Impoting the IDB_STATS functions here
from idb_stats.comments import get_comments
from idb_stats.functions import get_all_function_names, get_binary_functions_and_prototypes
from idb_stats.segments import get_all_segments

DEBUG_LOG = r"C:\Users\rev-win\Desktop\ida_debug.log"

# Logging Function For Headleass Ida
def log(msg):
    timestamp = datetime.datetime.now().isoformat()

    with open(DEBUG_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {msg}\n")

log("### SCRIPT STARTED ###\n")

def main():
    # Wait for auto-analysis to finish
    log("Waiting for auto analysis...")
    ida_auto.auto_wait()
    log("Auto analysis finished")



    args = idc.ARGV
    if len(args) < 2:
        log("Missing logfile argument")
        print("Usage: headless_script.py <logfile>")
        ida_pro.qexit(1)
        return

    logfile = args[1]
    log(f"Arguments {args}")
    log(f"Logfile: {logfile}")


    # -----------------------------------------------------------------
    # Perform your tasks here
    # -----------------------------------------------------------------
    try:
        results = {
            "Comments": get_comments()
            # , "Functions": get_all_function_names()
            , "Functions": get_binary_functions_and_prototypes()
            , "Segments": get_all_segments()
        }
    
        with open(logfile, "w") as f:
            json.dump(results, f, indent=4)
        log("Output written successfully")

    except Exception as e:
        with open(logfile, "a") as f:
            f.write(str(e))
        log("Exception occurred")
        ida_pro.qexit(1)
        return

    # -----------------------------------------------------------------
    # Performing tasks end here
    # -----------------------------------------------------------------

    # Exit IDA
    ida_pro.qexit(0)


if __name__ == "__main__":
    main()