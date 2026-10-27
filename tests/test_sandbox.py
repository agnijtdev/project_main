import pytest
from pathlib import Path
from devsecops_agent.sandbox.local_sandbox import LocalIsolatedSandbox


def test_local_sandbox_lifecycle(tmp_path):
    # Set up dummy source workspace
    source_file = tmp_path / "hello.py"
    source_file.write_text("print('hello world')", encoding="utf-8")

    sandbox = LocalIsolatedSandbox(str(tmp_path))
    sandbox.start()
    assert sandbox.is_running is True

    # Test reading existing file
    read_content = sandbox.read_file("hello.py")
    assert "hello world" in read_content

    # Test writing new file
    sandbox.write_file("test.txt", "isolated data")
    assert sandbox.read_file("test.txt") == "isolated data"

    # Test command execution
    result = sandbox.execute("python -c \"print('execution successful')\"")
    assert result.exit_code == 0
    assert "execution successful" in result.stdout

    # Test applying patch and resetting
    sandbox.apply_patch({"hello.py": "print('patched')"})
    assert "patched" in sandbox.read_file("hello.py")

    sandbox.reset()
    assert "hello world" in sandbox.read_file("hello.py")

    sandbox.stop()
    assert sandbox.is_running is False
