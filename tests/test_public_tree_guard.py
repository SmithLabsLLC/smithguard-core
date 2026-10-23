"""The public source guard recognizes literal and escaped personal home paths."""

import pytest

from tools.check_public_tree import PRIVATE_PATH


@pytest.mark.parametrize("separator", ["\\", "\\\\"])
def test_guard_recognizes_windows_home_paths(separator):
    value = separator.join(["C:", "Users", "example", "project"])
    assert PRIVATE_PATH.search(value.encode())


@pytest.mark.parametrize("root", ["home", "Users"])
def test_guard_recognizes_posix_home_paths(root):
    value = "/" + root + "/example/project"
    assert PRIVATE_PATH.search(value.encode())


def test_guard_allows_generic_service_paths():
    assert not PRIVATE_PATH.search(b"/var/lib/smithguard /opt/SmithGuard ./src")
