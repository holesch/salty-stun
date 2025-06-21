import base64
import dataclasses
import re
import subprocess
import tempfile

import pytest

DUMMY_PRIVATE_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)
DUMMY_PUBLIC_KEY_B64 = base64.b64encode(DUMMY_PRIVATE_KEY)


class ArgsRunner:
    def __init__(self, builddir):
        self._exe = builddir / "test-args"

    def parse_args(self, *args, input_=None):
        result = self.run(*args, input_=input_)
        lines = result.stdout.decode().splitlines()
        return Args(
            port=int(lines[0]),
            private_key=bytes.fromhex(lines[1]),
            level=int(lines[2]),
            max_sessions=int(lines[3]),
            sockfd=int(lines[4]),
            stdout=lines[5:],
        )

    def run(self, *args, input_=None):
        result = subprocess.run(
            [self._exe, *args],
            capture_output=True,
            input=input_,
            check=True,
        )
        assert result.stderr == b""
        return result

    def run_err(self, *args, input_=None):
        result = subprocess.run(
            [self._exe, *args],
            capture_output=True,
            input=input_,
            check=False,
        )
        assert result.returncode != 0
        assert result.stdout == b""
        return result


@dataclasses.dataclass
class Args:
    port: int
    private_key: bytes
    level: int
    max_sessions: int
    stdout: list[str]
    sockfd: int


@pytest.fixture
def args_runner(pytestconfig):
    return ArgsRunner(pytestconfig.getoption("builddir"))


def test_default_values(args_runner):
    args = args_runner.parse_args("-k", "-", input_=DUMMY_PUBLIC_KEY_B64)
    assert args.port == 51820
    assert args.private_key == DUMMY_PRIVATE_KEY
    assert args.level == 2
    assert args.max_sessions == 1024
    assert args.sockfd == -1
    assert args.stdout == []


def test_help(args_runner):
    result = args_runner.run("-h")
    assert result.stdout.startswith(b"usage: salty-stun")
    assert b"optional arguments:" in result.stdout
    for line in result.stdout.splitlines():
        assert len(line) < 80


def test_version(args_runner):
    result = args_runner.run("-V")
    assert re.match(rb"salty-stun \d+\.\d+\.\d+", result.stdout)


def test_args(args_runner):
    args = args_runner.parse_args(
        "-p",
        "1234",
        "-k",
        "-",
        "-K",
        "-",
        "-l",
        "debug",
        "-n",
        "42",
        "-f",
        "3",
        input_=DUMMY_PUBLIC_KEY_B64,
    )
    assert args.port == 1234
    assert args.private_key == DUMMY_PRIVATE_KEY
    assert args.level == 3
    assert args.max_sessions == 42
    assert args.sockfd == 3
    assert args.stdout == ["key log"]


def test_key_log_file(args_runner):
    with tempfile.NamedTemporaryFile() as key_log_file:
        args_runner.parse_args(
            "-k", "-", "-K", key_log_file.name, input_=DUMMY_PUBLIC_KEY_B64
        )
        assert key_log_file.read() == b"key log\n"


def test_private_key_file(args_runner):
    with tempfile.NamedTemporaryFile() as private_key_file:
        private_key_file.write(DUMMY_PUBLIC_KEY_B64)
        private_key_file.flush()
        args = args_runner.parse_args("-k", private_key_file.name)
        assert args.private_key == DUMMY_PRIVATE_KEY


def test_private_key_with_trailing_whitespace(args_runner):
    args = args_runner.parse_args(
        "-k", "-", input_=DUMMY_PUBLIC_KEY_B64 + b" \t\n\r\v\f"
    )
    assert args.private_key == DUMMY_PRIVATE_KEY


def test_missing_option_argument(args_runner):
    result = args_runner.run_err("-p")
    assert b"error: option -p requires an argument" in result.stderr


def test_unrecognized_option(args_runner):
    result = args_runner.run_err("-Z")
    assert b"error: unrecognized option: -Z" in result.stderr


def test_unknown_argument(args_runner):
    result = args_runner.run_err("foo")
    assert b"error: unrecognized argument: foo" in result.stderr


def test_invalid_key_log_file(args_runner):
    result = args_runner.run_err("-K", "/nonexistent")
    assert b'error: failed to open key log file "/nonexistent"' in result.stderr


def test_invalid_private_key_file(args_runner):
    result = args_runner.run_err("-k", "/nonexistent")
    assert b'error: failed to open key file "/nonexistent"' in result.stderr


def test_key_file_too_short(args_runner):
    with tempfile.NamedTemporaryFile() as private_key_file:
        private_key_file.write(b"short")
        private_key_file.flush()
        result = args_runner.run_err("-k", private_key_file.name)
        assert b"error: not enough data in key file" in result.stderr


def test_private_key_trailing_characters(args_runner):
    result = args_runner.run_err("-k", "-", input_=DUMMY_PUBLIC_KEY_B64 + b"X")
    assert (
        b"error: found trailing character in key file \"<stdin>\": 'X'" in result.stderr
    )


def test_invalid_private_key(args_runner):
    result = args_runner.run_err("-k", "-", input_=b"#" + DUMMY_PUBLIC_KEY_B64[1:])
    assert b'error: failed to decode key in "<stdin>"' in result.stderr


@pytest.mark.parametrize("port", ["0", "65536", "x", "1x"])
def test_invalid_port(args_runner, port):
    result = args_runner.run_err("-p", port)
    assert b"error: argument -p: invalid port" in result.stderr


def test_max_sessions_max_value(args_runner):
    max_value = 0x800000
    args = args_runner.parse_args(
        "-k", "-", "-n", str(max_value), input_=DUMMY_PUBLIC_KEY_B64
    )
    assert args.max_sessions == max_value


def test_max_sessions_too_large(args_runner):
    max_value = 0x800000 + 1
    result = args_runner.run_err(
        "-k", "-", "-n", str(max_value + 1), input_=DUMMY_PUBLIC_KEY_B64
    )
    assert b"error: argument -n: invalid number of sessions" in result.stderr
