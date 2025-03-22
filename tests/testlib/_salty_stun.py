import base64
import contextlib
import subprocess

from . import _crypto as crypto


class SaltyStun:
    def __init__(self, bin_path, port=51820, key_log=False, max_sessions=None):
        self._args = [bin_path, "-l", "3", "-k", "-", "-p", str(port)]
        self._port = port
        self._stdout = None

        if key_log:
            self._args.extend(["-K", "-"])

        if max_sessions is not None:
            self._args.extend(["-n", str(max_sessions)])

        result = subprocess.run(["wg", "genkey"], stdout=subprocess.PIPE, check=True)
        self._private_key_b64 = result.stdout.rstrip()

        result = subprocess.run(
            ["wg", "pubkey"],
            input=self._private_key_b64,
            stdout=subprocess.PIPE,
            check=True,
        )
        public_key = base64.b64decode(result.stdout)
        self._public_key = crypto.X25519PublicKey.from_public_bytes(public_key)

    def __enter__(self):
        with contextlib.ExitStack() as stack:
            proc = stack.enter_context(
                subprocess.Popen(
                    self._args, stdin=subprocess.PIPE, stdout=subprocess.PIPE
                )
            )
            stack.callback(proc.terminate)

            proc.stdin.write(self._private_key_b64)
            proc.stdin.close()

            self._stdout = proc.stdout

            self._stack = stack.pop_all()
            self._stack.__enter__()
            return self

    def __exit__(self, exc_type, exc, tb):
        self._stack.__exit__(exc_type, exc, tb)

    @property
    def port(self):
        return self._port

    @property
    def public_key(self):
        return self._public_key

    @property
    def stdout(self):
        return self._stdout

    @property
    def private_key_b64(self):
        return self._private_key_b64
