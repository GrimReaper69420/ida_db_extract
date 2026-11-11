import idautils
import ida_segment

def get_all_segments():
    """Iterates through all segments in the IDB and prints their names and addresses."""
    segments = []
    
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg:
            seg_name = ida_segment.get_segm_name(seg)
            segments.append(f"0x{seg.start_ea:X} : {seg_name}")

    
    return segments