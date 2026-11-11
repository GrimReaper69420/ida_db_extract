import ida_kernwin
import ida_diskio

import subprocess
import threading
import shutil
import os
import sys

# 1. Define the Native Form
class HeadlessRunnerForm(ida_kernwin.Form):
    def __init__(self):
        template = r"""BUTTON YES* Analyze
BUTTON CANCEL Cancel
Run Headless Analysis

Please select the target IDB database and output folder.

<#Select target IDB/i64 file#Target IDB:{fIdb}>
<#Select output directory#Output Dir:{dOut}>
"""
        controls = {
            'fIdb': ida_kernwin.Form.FileInput(open=True),
            'dOut': ida_kernwin.Form.DirInput()
        }
        super().__init__(template, controls)


# 2. Background Worker Function
def run_analysis_in_background(script_name, out_dir, idb_path):
    """Executes in a background Python thread to keep IDA responsive."""
    cwd = os.getcwd()
    
    ida_executable = sys.executable

    idb_name = idb_path.split('\\')[-1]
    stats_path = os.path.join(out_dir, idb_name + ".stats")

    # Creating this to work on temporary idb ather then original
    temp_idb_path = os.path.join(out_dir, f"temp_{os.getpid()}_{idb_name}")

    user_plugins = ida_diskio.get_user_idadir() + os.sep + "plugins"
    script_path = os.path.join(user_plugins, "ida_db_extract", script_name)

#(NOTE) THese are Debug Prints
    ida_kernwin.msg(f"[+] User Plugins Path: {user_plugins}")
    ida_kernwin.msg(f"[+] Script Path {script_path}\n")

    script_flag = f'-S"{script_path}" "{stats_path}"'

    try:
        # Creating temporary IDB file
        shutil.copy2(idb_path, temp_idb_path)

        cmd = [
            ida_executable,
            "-A",
            script_flag,
            temp_idb_path
        ]

#(NOTE) THese are Debug Prints
        ida_kernwin.msg(f"[+] IDB name {idb_name}\n")
        ida_kernwin.msg(f"[+] Stats Path: {stats_path}\n")
        ida_kernwin.msg(f"[+] Starting background headless job for: {os.path.basename(temp_idb_path)}\n")
        ida_kernwin.msg(f"[+] The command looks like: {cmd}\n")

        # Blocks ONLY this background thread until the process completes
        result = subprocess.run(cmd, capture_output=True, text=True)

        # Function to safely alert the user on IDA's main UI thread
        def notify_completion():
            if return_code == 0:
                ida_kernwin.info(f"Analysis Complete!\n\nIDB: {os.path.basename(temp_idb_path)}\nSaved to: {out_dir}")
                ida_kernwin.msg(f"[+] Headless process finished successfully (exit code 0).\n")
            else:
                ida_kernwin.warning(f"Analysis Failed!\n\nProcess exited with code {return_code}.\nCheck Output window for logs.")
                ida_kernwin.msg(f"[!] Headless STDERR:\n{result.stderr}\n")

        # Safely pass execution back to IDA's main thread for UI alerts
        ida_kernwin.execute_sync(notify_completion, ida_kernwin.MFF_FAST)

    except Exception as e:
        def notify_error():
            ida_kernwin.warning(f"Failed to execute headless process:\n{str(e)}")
        ida_kernwin.execute_sync(notify_error, ida_kernwin.MFF_FAST)
    
    finally:
        # 4. Cleanup: Delete the temporary database copy (and its sidecar files if generated)
        if os.path.exists(temp_idb_path):
            try:
                os.remove(temp_idb_path)
                print(f"[+] Cleaned up temporary database: {temp_idb_path}")
            except Exception as cleanup_error:
                print(f"[!] Failed to delete temporary file {temp_idb_path}: {cleanup_error}")

# 3. Main Trigger Function
def prompt_and_run_headless():
    """Displays the form and spawns the background thread."""
    form = HeadlessRunnerForm()
    form.Compile()
    
    try:
        if form.Execute() == 1:
            idb_path = form.fIdb.value
            out_dir = form.dOut.value
            
            if not idb_path or not os.path.exists(idb_path):
                ida_kernwin.warning("Invalid IDB path selected.")
                return
            if not out_dir or not os.path.isdir(out_dir):
                ida_kernwin.warning("Invalid output directory selected.")
                return
            

            script_name = r"ida_db_extract.py"
            
            
            # Spawn background thread so IDA GUI stays 100% active while waiting
            worker_thread = threading.Thread(
                target=run_analysis_in_background,
                args=(script_name, out_dir, idb_path),
                daemon=True
            )
            worker_thread.start()

    finally:
        form.Free()