import os

import datetime
import pytest
import subprocess
import tempfile
import logging

from selinux import SELinuxAVCChecker
from pytest_client_tools.util import loop_until

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def install_katello_rpm(test_config):
    if "satellite" in test_config.environment:
        # install katello rpm before register system against Satellite
        satellite_hostname = test_config.get("candlepin", "host")
        cmd = [
            "rpm",
            "-Uvh",
            "http://%s/pub/katello-ca-consumer-latest.noarch.rpm" % satellite_hostname,
        ]
        subprocess.check_call(cmd)
    yield
    if "satellite" in test_config.environment:
        cmd = "rpm -qa 'katello-ca-consumer*' | xargs rpm -e"
        subprocess.check_call(cmd, shell=True)


@pytest.fixture(scope="session")
def register_subman(external_candlepin, install_katello_rpm, subman_session, test_config):
    if "satellite" in test_config.environment:
        subman_session.register(
            activationkey=test_config.get("candlepin", "activation_keys"),
            org=test_config.get("candlepin", "org"),
        )
    else:
        subman_session.register(
            username=test_config.get("candlepin", "username"),
            password=test_config.get("candlepin", "password"),
        )
    yield subman_session


@pytest.fixture(scope="session", autouse=True)
def ensure_insights_directory():
    """
    Ensure /var/lib/insights/ directory exists.

    insights-client expects this directory to exist for temporary GPG operations.
    In image-mode or fresh installations, this directory may not exist yet,
    causing insights-client to fail with FileNotFoundError when trying to
    create temporary directories for GPG validation.

    This is a workaround for insights-client bug where it tries to validate
    eggs even when they don't exist and the directory doesn't exist yet.
    """
    insights_dir = "/var/lib/insights"
    if not os.path.exists(insights_dir):
        try:
            os.makedirs(insights_dir, mode=0o755, exist_ok=True)
            logger.info(f"Created {insights_dir} directory for insights-client")
        except Exception as e:
            logger.warning(f"Failed to create {insights_dir}: {e}")
    yield


@pytest.fixture(scope="session", autouse=True)
def insights_core_workaround():
    """
    Workaround for https://issues.redhat.com/browse/RHINENG-21918
    When insights-client is started by a user (running shell in unconfined mode)
    and the insights-client is run in insights_client_t SELinux context type
    (effectively switching the next python process that executes the insights_core
    code to insights_core_t SELinux context type), printing to PTY or pipe
    (through inherited file descriptor) that belongs to the user is not allowed.
    This Workaround fixture allows these actions in the active SELinux policy.
    """
    # Check if SELinux is available and enabled
    try:
        result = subprocess.run(
            ["getenforce"],
            capture_output=True,
            text=True,
            timeout=5
        )
        selinux_status = result.stdout.strip()

        if result.returncode != 0 or selinux_status in ["Disabled", ""]:
            logger.warning(
                f"SELinux not available or disabled (status: {selinux_status}), "
                "skipping insights_core workaround"
            )
            yield
            return
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning(
            f"SELinux tools not installed or not responding: {e}, "
            "skipping insights_core workaround"
        )
        yield
        return

    policy = """module core_output 1.0;

require {
  type insights_core_t;
  type unconfined_t;
  type user_devpts_t;
  class fifo_file write;
  class chr_file { ioctl read write };
}

#============= insights_core_t ==============
allow insights_core_t unconfined_t:fifo_file write;
allow insights_core_t user_devpts_t:chr_file { ioctl read write };
"""

    module_installed = False
    origdir = os.getcwd()
    with tempfile.TemporaryDirectory() as tempdirname:
        try:
            os.chdir(tempdirname)
            with open("core_output.te", "wt") as selinux_file:  # codespell:ignore te
                selinux_file.write(policy)
            subprocess.run(
                [
                    "checkmodule",
                    "-M",
                    "-m",
                    "-o",
                    "core_output.mod",
                    "core_output.te",  # codespell:ignore te
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["semodule_package", "-o", "core_output.pp", "-m", "core_output.mod"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["semodule", "-i", "core_output.pp"],
                check=True,
                capture_output=True,
            )
            module_installed = True
            logger.info("Successfully installed SELinux workaround module 'core_output'")

        except subprocess.CalledProcessError as e:
            # Log the error but don't fail the tests
            stderr = e.stderr.decode() if e.stderr else "No stderr"
            logger.warning(
                f"Failed to install SELinux workaround module: {e}\n"
                f"Command: {' '.join(e.cmd)}\n"
                f"Return code: {e.returncode}\n"
                f"Stderr: {stderr}\n"
                "Tests will continue without the SELinux workaround."
            )
        except Exception as e:
            logger.warning(f"Unexpected error applying SELinux workaround: {e}")
        finally:
            os.chdir(origdir)

    yield

    # Cleanup: Remove the SELinux module if it was installed
    if module_installed:
        try:
            subprocess.run(
                ["semodule", "-r", "core_output"],
                check=True,
                capture_output=True
            )
            logger.info("Successfully removed SELinux workaround module 'core_output'")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to remove SELinux module 'core_output': {e}")


@pytest.fixture(autouse=True)
def check_no_egg_content():
    """
    Check that there is no egg-based content on the system.

    Note: insights-core < 3.8 still requires .egg files for version detection.
    This fixture handles this gracefully by skipping egg cleanup when using
    older insights-core versions that need them.
    """
    yield

    # Check if insights-core version supports RPM-based operation (no eggs needed)
    insights_core_needs_eggs = False
    try:
        result = subprocess.run(
            ["rpm", "-q", "--queryformat", "%{VERSION}", "insights-core"],
            capture_output=True,
            text=True,
            check=True
        )
        core_version = result.stdout.strip()
        # insights-core < 3.8 still needs .egg files
        if core_version.startswith("3.7") or core_version.startswith("3.6"):
            insights_core_needs_eggs = True
            logger.info(
                f"insights-core {core_version} requires .egg files for version detection. "
                "Skipping egg cleanup."
            )
    except subprocess.CalledProcessError:
        logger.warning("Could not determine insights-core version, skipping egg cleanup")
        insights_core_needs_eggs = True

    egg_based_directory = "/var/lib/insights/"
    allowed_files = [
        "private-keys-v1.d",
        "pubring.kbx",
        "pubring.kbx~",
        "trustdb.gpg",
        "host-details.json",
    ]

    # Only clean up .egg files if insights-core doesn't need them
    if not insights_core_needs_eggs:
        try:
            for name in os.listdir(egg_based_directory):
                if name.endswith('.egg') or name.endswith('.egg.asc'):
                    egg_path = os.path.join(egg_based_directory, name)
                    try:
                        os.remove(egg_path)
                        logger.warning(f"Cleaned up legacy egg file: {egg_path}")
                    except Exception as e:
                        logger.error(f"Failed to remove {egg_path}: {e}")
        except Exception as e:
            logger.error(f"Failed to list directory {egg_based_directory}: {e}")
    else:
        # With old insights-core, .egg files are expected, so add them to allowed list
        allowed_files.extend(["last_stable.egg", "newest.egg", "last_stable.egg.asc", "newest.egg.asc"])

    # Check for unexpected content
    unexpected_files = []
    try:
        for name in os.listdir(egg_based_directory):
            if name not in allowed_files and not (insights_core_needs_eggs and name.endswith('.egg')):
                unexpected_files.append(name)
    except Exception as e:
        logger.error(f"Failed to check directory {egg_based_directory}: {e}")

    if unexpected_files:
        pytest.fail(
            f"Unexpected additional content found in {egg_based_directory}: {', '.join(unexpected_files)}"
        )

    # Clean up legacy egg-based files in /etc/insights-client/
    # Only if insights-core doesn't need them
    if not insights_core_needs_eggs:
        egg_based_files = [
            "/etc/insights-client/redhattools.pub.gpg",
            "/etc/insights-client/rpm.egg",
            "/etc/insights-client/rpm.egg.asc",
            "/etc/insights-client/.insights-core.etag",
            "/etc/insights-client/.insights-core-gpg-sig.etag",
        ]
        for file_path in egg_based_files:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    logger.warning(f"Cleaned up legacy egg-based file: {file_path}")
                except Exception as e:
                    logger.error(f"Failed to remove {file_path}: {e}")


def check_is_bootc_system():
    """
    Check if the system is a bootc enabled system.
    This function duplicates the logic from pytest-client-tools' is_bootc_system fixture
    so it can be used in pytest.skipif decorators (which run at collection time).
    """
    try:
        bootc_status = subprocess.run(
            ["bootc", "status", "--format", "humanreadable"],
            capture_output=True,
            text=True,
        )
        return (bootc_status.returncode == 0) and (
            not bootc_status.stdout.strip().startswith("System is not deployed via bootc")
        )
    except FileNotFoundError:
        return False


def wait_for_services_to_finish(services=None):
    if services is None:
        services = (
            "insights-client.service",
            "insights-client-results.service",
        )
    logger.debug(f"{datetime.datetime.now()} Waiting for systemd services to finish: {services}")
    for service in services:
        if not loop_until(
            lambda: subprocess.run(["systemctl", "is-active", "--quiet", service]).returncode != 0
        ):
            logger.info(f"Systemd service is still running: {service}")
    logger.debug(f"{datetime.datetime.now()} Finished waiting for systemd services to finish")


def add_known_avcs_to_skiplist(avc_checker):
    avc_checker.skip_avc_entry_by_fields(
        {
            "subj": "system_u:system_r:insights_client_t:s0",
            "syscall": "openat",
            "permission": "search",
            "obj": "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
        }
    )  # Bug: https://issues.redhat.com/browse/CCT-2009
    avc_checker.skip_avc_entry_by_fields(
        {
            "subj": "system_u:system_r:insights_client_t:s0",
            "syscall": "fstat",
            "permission": "getattr",
            "obj": "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
        }
    )  # Bug: https://issues.redhat.com/browse/CCT-2009
    avc_checker.skip_avc_entry_by_fields(
        {
            "subj": "system_u:system_r:rhsmcertd_t:s0",
            "syscall": "openat",
            "permission": "read",
            "obj": "unconfined_u:object_r:admin_home_t:s0",
        }
    )  # Testing farm misconfiguration: https://issues.redhat.com/browse/TFT-4293


@pytest.fixture(autouse=True)
def check_avcs(request):
    """
    Monitor SELinux AVCs during the test execution.
    This fixture is applied to all tests and can be configured following way:
     * Skipping all SELinux AVCs (only logging them):
        Use this fixture explicitly by the test (adding `check_avcs` to test arguments)
        and then at the beginning of the test call: `check_avcs.skip_all_avcs()`
     * Skipping selected SELinux AVCs (only logging them)
        Use this fixture explicitly by the test (adding `check_avcs` to test arguments)
        and then at the beginning of the test call one of `SELinuxAVCChecker` skip methods.

    This pytest fixture yields instance of SELinuxAVCChecker class.
    """
    with SELinuxAVCChecker() as checker:
        add_known_avcs_to_skiplist(checker)
        # WORKAROUND: Wait for important services to finish be finished before running
        # the test to ensure stable environment. If the services are not finished and
        # the test starts, it may very easily happen, that the test starts touching
        # files used by the service bringing the system to undefined state eventually
        # also raising unexpected SELinux AVCs. This waiting should not belong here
        # and should be implemented somehow differently "the pytest way".
        wait_for_services_to_finish()
        yield checker
        # WORKAROUND: Wait for the services that are implicitly part of the test
        # to finish in order to ensure that all the operations done by those services
        # are monitored for the SELinux AVCs. The tests generally do not care about
        # status of services. It is crucial for the SELinux AVCs monitoring to
        # capture all events even those that happen on the background to be able to
        # associate those SELinux AVCs to the relevant tests during which those AVCs
        # occurred.
        wait_for_services_to_finish()
    logger.info(
        "All AVCs detected during test execution:\n"
        + "\n".join([str(denial) for denial in checker.get_avcs(skiplisted=False)])
    )
    denials = tuple(checker.get_avcs())
    if denials:
        pytest.fail(
            "AVCs detected during test run!\n" + "\n".join([str(denial) for denial in denials])
        )
