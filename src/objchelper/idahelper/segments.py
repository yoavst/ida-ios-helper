from collections.abc import Iterator
from dataclasses import dataclass

import ida_funcs
import ida_segment
from ida_funcs import func_t
from ida_segment import segment_t


@dataclass
class Segment:
    name: str
    start_ea: int
    end_ea: int
    size: int
    cls: str

    def __repr__(self):
        return f"[{self.start_ea:#x}-{self.end_ea:#x}] {self.name} size:{self.size} cls:{self.cls}"

    def __hash__(self) -> int:
        return hash((self.start_ea, self.end_ea))

    @staticmethod
    def from_segment(segment: segment_t) -> "Segment":
        return Segment(
            ida_segment.get_segm_name(segment),
            segment.start_ea,
            segment.end_ea,
            segment.end_ea - segment.start_ea,
            ida_segment.get_segm_class(segment),
        )

    def functions(self) -> Iterator[func_t]:
        """Iterate all functions that are defined in the given segment"""
        func_ea = self.start_ea
        func = ida_funcs.get_func(func_ea)
        if func is None:
            # No function there, try to get the next one
            func = ida_funcs.get_next_func(func_ea)

        while func is not None and func.start_ea < self.end_ea:
            yield func
            func = ida_funcs.get_next_func(func.start_ea)

    @property
    def base_name(self) -> str:
        """If the name is a.b.c:__d then return a.b.c ; Otherwise, return the original name"""
        return self.name.split(":")[0]


def get_segments(cls: str | None = None) -> list[Segment]:
    """Get all segments in the executable, optionally filter it by specific class"""
    segments = []
    for i in range(ida_segment.get_segm_qty()):
        seg = Segment.from_segment(ida_segment.getnseg(i))
        if cls is None or seg.cls == cls:
            segments.append(seg)
    return segments


def get_segment_by_name(name: str) -> Segment | None:
    """Get segment with the given name or none if non existant"""
    seg = ida_segment.get_segm_by_name(name)
    if seg is None:
        return None
    return Segment.from_segment(seg)
