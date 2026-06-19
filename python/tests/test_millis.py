"""Unit tests for the timeout->milliseconds conversion.

Pure logic, but it lives in dotvault.__init__ which loads the native library on
import, so conftest's skip-when-unbuilt still applies.
"""

import dotvault
import pytest

_millis = dotvault._millis


@pytest.mark.parametrize(
    "timeout, expected",
    [
        (None, 0),       # no deadline
        (0, 0),          # zero -> no deadline
        (-1.0, 0),       # negative -> no deadline (never negative ms)
        (0.0004, 0),     # sub-millisecond truncates to 0 == no deadline (documented)
        (0.001, 1),      # smallest real deadline
        (1, 1000),
        (2.5, 2500),
    ],
)
def test_millis(timeout, expected):
    assert _millis(timeout) == expected
