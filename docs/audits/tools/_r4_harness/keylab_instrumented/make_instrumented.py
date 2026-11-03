#!/usr/bin/env python3
"""Create an instrumented copy of keylab/slot.go with named hook points.

The ONLY change is the insertion of `r4hook("<point>")` calls; no statement of the
original is altered or reordered. Usage: make_instrumented.py <slot.go> <out_dir>
"""
import sys, pathlib

src = pathlib.Path(sys.argv[1]).read_text()
out = pathlib.Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)

patches = [
    # R4-KLM-01: between the closing check and the ticket CAS in reserve()
    ("\t\tif k.state.Load()&closingBit != 0 {\n\t\t\treturn 0, errClosed\n\t\t}\n\t\tif k.next.CompareAndSwap(n, n+1) {",
     "\t\tif k.state.Load()&closingBit != 0 {\n\t\t\treturn 0, errClosed\n\t\t}\n\t\tr4hook(\"reserve:checked\")\n\t\tif k.next.CompareAndSwap(n, n+1) {"),
    # admitted work starting after closing: between reserve() and process()
    ("\tout, err := k.p.process(seq, input)",
     "\tr4hook(\"seal:reserved\")\n\tout, err := k.p.process(seq, input)"),
    # R4-KLM-02: after the post-process closing check, before returning the record
    ("\tif err != nil {\n\t\tclear(out)\n\t\treturn record{}, err\n\t}\n\treturn record{sequence: seq, payload: out}, nil",
     "\tr4hook(\"seal:postcheck\")\n\tif err != nil {\n\t\tclear(out)\n\t\treturn record{}, err\n\t}\n\treturn record{sequence: seq, payload: out}, nil"),
    # R4-KLM-03: after the wipe claim, before wipe()
    ("\t\t\tk.p.wipe()\n\t\t\tclose(k.done)",
     "\t\t\tr4hook(\"finalize:claimed\")\n\t\t\tk.p.wipe()\n\t\t\tclose(k.done)"),
]
for old, new in patches:
    if src.count(old) != 1:
        sys.exit(f"pattern not found exactly once: {old[:60]!r}")
    src = src.replace(old, new)
(out / "slot.go").write_text(src)
(out / "r4hook.go").write_text('''//go:build qazwire_exp

package keylab

import "sync/atomic"

// r4hook is a no-op unless a test installs a handler. Instrumented copy only.
var r4hookFn atomic.Pointer[func(point string)]

func r4hook(point string) {
	if f := r4hookFn.Load(); f != nil {
		(*f)(point)
	}
}
''')
