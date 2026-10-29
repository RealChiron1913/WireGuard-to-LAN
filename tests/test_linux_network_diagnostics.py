import sys

import pytest

from linux_network import run


def test_failing_command_reports_stderr_and_exit_code():
    with pytest.raises(RuntimeError, match='sentinel syntax error') as failure:
        run(sys.executable, '-c', "import sys; sys.stderr.write('sentinel syntax error'); sys.exit(7)")
    assert 'Command failed (7)' in str(failure.value)


def test_expected_failure_can_be_inspected_without_raising():
    result = run(sys.executable, '-c', "import sys; sys.stderr.write('expected failure'); sys.exit(7)", check=False)
    assert result.returncode == 7
    assert result.stderr == 'expected failure'
