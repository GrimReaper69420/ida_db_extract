import datetime
import ida_pro
import os

DEBUG_LOG = r"C:\Users\rev-win\Desktop\ida_debug.log"

with open(DEBUG_LOG, "a", encoding="utf-8") as f:
    f.write(
        f"Script started: {datetime.datetime.now()}\n"
    )

ida_pro.qexit(0)