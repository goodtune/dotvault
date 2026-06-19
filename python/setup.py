"""setuptools shim that compiles the cgo c-shared bridge into the package.

The actual binding metadata lives in pyproject.toml; this file exists for two
reasons setuptools can't express declaratively:

  1. Force a PLATFORM wheel. The package ships a compiled native library, so it
     must not be tagged ``py3-none-any`` (that would let pip install it on a
     mismatched OS/arch). ``BinaryDistribution.has_ext_modules() -> True`` makes
     setuptools tag the wheel with the running interpreter's platform.

  2. Build the native library. ``go build -buildmode=c-shared`` emits
     ``_dotvault.<ext>`` into the package directory before the files are
     collected. The Go module root is the REPOSITORY root (one level above this
     ``python/`` directory), located by walking up for go.mod.

Build context matters: when pip builds from an sdist in an isolated dir the
parent Go module is NOT present, so the native library must already be built
and sitting in ``src/dotvault/`` (this is what the CI wheel job and the
repo-root ``make python-lib`` target arrange). When building from a full
checkout (``pip install ./python`` or ``python -m build`` in a worktree) the Go
module IS reachable and we build the library on the fly. The logic below covers
both: use an existing library, else build it if the Go module is reachable,
else fail with a clear message.

Override knobs (env):
  DOTVAULT_SKIP_GO_BUILD=1   never invoke go; require a prebuilt library.
  DOTVAULT_FORCE_GO_BUILD=1  rebuild even if a library is already present.
"""

import os
import subprocess
import sys

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.dist import Distribution

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.join(HERE, "src", "dotvault")


def _library_name():
    """Native library filename for the building platform."""
    if sys.platform == "win32":
        return "_dotvault.dll"
    if sys.platform == "darwin":
        return "_dotvault.dylib"
    return "_dotvault.so"


def _find_go_module_root(start):
    """Walk up from ``start`` looking for the go.mod that defines the module."""
    path = start
    while True:
        if os.path.isfile(os.path.join(path, "go.mod")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent


def _build_native_library():
    """Ensure ``src/dotvault/<libname>`` exists, building it with go if needed."""
    lib_path = os.path.join(PKG_DIR, _library_name())
    have_lib = os.path.exists(lib_path)

    if os.environ.get("DOTVAULT_SKIP_GO_BUILD"):
        if not have_lib:
            raise SystemExit(
                f"DOTVAULT_SKIP_GO_BUILD set but {lib_path} is missing; "
                "build the native library first"
            )
        return

    force = bool(os.environ.get("DOTVAULT_FORCE_GO_BUILD"))
    if have_lib and not force:
        return

    module_root = _find_go_module_root(HERE)
    if module_root is None:
        if have_lib:
            return  # prebuilt library present; isolated build with no Go module.
        raise SystemExit(
            "dotvault: cannot find the Go module (go.mod) to build the native "
            f"library, and no prebuilt {lib_path} is present. Build from a full "
            "checkout or pre-build the library (see python/README.md)."
        )

    # CGO is forced on (c-shared requires it); GOOS/GOARCH are inherited from
    # the environment. This assumes a NATIVE build — the wheel is tagged for the
    # running interpreter's platform (BinaryDistribution), so a cross-compiling
    # GOARCH in the env would mint a wheel whose native library mismatches its
    # tag. Cross-builds are out of scope; build on the target platform.
    env = dict(os.environ, CGO_ENABLED="1")
    cmd = [
        "go", "build", "-buildmode=c-shared",
        "-o", lib_path, "./python/bridge",
    ]
    print("dotvault: building native bridge:", " ".join(cmd), flush=True)
    subprocess.check_call(cmd, cwd=module_root, env=env)
    # go also drops a _dotvault.h header next to the lib; it is not needed at
    # runtime and we do not want it in the wheel, so remove it if present.
    header = os.path.splitext(lib_path)[0] + ".h"
    if os.path.exists(header):
        os.remove(header)


class BinaryDistribution(Distribution):
    """Forces a platform-specific (non-pure) wheel tag."""

    def has_ext_modules(self):  # noqa: D401 - setuptools hook
        return True


class BuildPyWithGo(build_py):
    """Build the native library before collecting package files."""

    def run(self):
        _build_native_library()
        super().run()


setup(
    distclass=BinaryDistribution,
    cmdclass={"build_py": BuildPyWithGo},
)
