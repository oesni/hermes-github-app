"""Protected-file checks. Host tool and Docker configuration are outside this plugin."""
import tempfile
from pathlib import Path
import pytest
from hermes_github_app.isolation import IsolationError
from hermes_github_app.runtime import HostBoundary
from hermes_github_app.secure_files import SecureFileError, check_secure_file, read_secure_file


def test_secure_file_diagnostics_keep_path_and_permissions_distinct():
    root = Path(__file__).resolve().parents[1] / '.test-private'
    root.mkdir(exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=root) as directory:
        private = Path(directory)
        key = private / 'sensitive-name.pem'
        key.write_text('TEST-ONLY-NONCREDENTIAL')
        key.chmod(0o600)
        link = private / 'link.pem'
        link.symlink_to(key)
        for path in ['relative-secret-name', str(private / 'missing-secret-name'), str(link), str(private)]:
            with pytest.raises(SecureFileError) as error:
                check_secure_file(path)
            assert error.value.category == 'path'
            assert 'secret-name' not in str(error.value)
        key.chmod(0o644)
        with pytest.raises(SecureFileError) as error:
            check_secure_file(str(key))
        assert error.value.category == 'permissions'
        key.chmod(0o600)
        private.chmod(0o770)
        try:
            with pytest.raises(SecureFileError) as error:
                check_secure_file(str(key))
            assert error.value.category == 'permissions'
        finally:
            private.chmod(0o700)
        with pytest.raises(SecureFileError) as error:
            read_secure_file(str(key), 1)
        assert error.value.category == 'size'
        assert 'TEST-ONLY' not in str(error.value)


def test_host_boundary_rechecks_both_files_and_stops(tmp_path):
    root = Path(__file__).resolve().parents[1] / '.test-private'
    root.mkdir(exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=root) as directory:
        private = Path(directory)
        config = private / 'config.yaml'
        key = private / 'key.pem'
        for path in (config, key):
            path.write_text('TEST-ONLY-NONCREDENTIAL')
            path.chmod(0o600)
        boundary = HostBoundary(str(config), str(key))
        boundary.check()
        key.chmod(0o644)
        with pytest.raises(SecureFileError):
            boundary.check()
        key.chmod(0o600)
        boundary.close()
        with pytest.raises(IsolationError):
            boundary.check()
