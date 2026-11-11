# idb_stats/comments.py

import ida_segment
import idautils
import idc


def get_comments():
    comments = []

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)

        for ea in idautils.Heads(seg.start_ea, seg.end_ea):

            cmt = idc.get_cmt(ea, False)
            if cmt:
                comments.append({
                    "address": ea,
                    "repeatable": False,
                    "text": cmt,
                })

            rcmt = idc.get_cmt(ea, True)
            if rcmt:
                comments.append({
                    "address": ea,
                    "repeatable": True,
                    "text": rcmt,
                })

    return comments