#!/usr/bin/env python3
"""Create an instrumented copy of sessionlab/session.go (PR #13, 45984d7, or the
R4.2-patched copy produced by apply_r42_fix.py).

The ONLY change is the insertion of r42hook("<point>") calls; no original
statement is altered or reordered. Fails unless every pattern matches once.
Usage: make_instrumented.py <session.go> <out_dir>
"""
import pathlib
import re
import sys

src = pathlib.Path(sys.argv[1]).read_text()
out = pathlib.Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
patches = [
    # between a successful seal and the generation fence under session.mu
    (r"\n(\t+)s\.mu\.Lock\(\)\n(\t+)// An old in-flight operation can outlive TWO rotations",
     '\n\\1r42hook("prepare:beforeLock")\n\\1s.mu.Lock()\n\\2// An old in-flight operation can outlive TWO rotations'),
    # between the wipe-failure latch and the asynchronous emergency
    (r"\n(\t+)s\.faults\.Or\(faultWipeFailed\)\n(\t+)go s\.beginEmergency\(\)",
     '\n\\1s.faults.Or(faultWipeFailed)\n\\1r42hook("onFail:latched")\n\\2go s.beginEmergency()'),
]
for pat, new in patches:
    src, n = re.subn(pat, new, src)
    if n != 1:
        sys.exit(f"pattern not found exactly once: {pat[:50]!r}")
(out / "session.go").write_text(src)
(out / "r42hook.go").write_text('''//go:build qazwire_exp

package sessionlab

import "sync/atomic"

// r42hook is a no-op unless a test installs a handler. Instrumented copy only.
var r42hookFn atomic.Pointer[func(point string)]

func r42hook(point string) {
	if f := r42hookFn.Load(); f != nil {
		(*f)(point)
	}
}
''')
