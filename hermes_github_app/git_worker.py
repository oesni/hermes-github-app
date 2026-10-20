"""Internal resource-limited Git child; never an agent-facing command interface."""
import os
import resource
import sys


def main():
    # Applied in an isolated child rather than preexec_fn in a threaded host.
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    if sys.platform.startswith('linux'):
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    os.execv(sys.argv[1], sys.argv[1:])


if __name__ == '__main__':
    main()
