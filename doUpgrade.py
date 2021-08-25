""" SRX MNHA software upgrade utility

This script will assist in the software upgrade of SRX MNHA devices

"""
import configparser
import shutil
import os
import sys
import logging
import argparse
import time

from dataclasses import dataclass
from datetime import datetime
import subprocess
from pathlib import Path
from jnpr.jsnapy import SnapAdmin
from jnpr.junos import Device as jdevice
from jnpr.junos.utils.sw import SW
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConnectError
from jnpr.junos.utils.start_shell import StartShell

import yaml
import upgrade_utils as utils


@dataclass
class Device:
    ''' Class for keeping track of a device and its information '''
    name: str
    ip: str
    port: int           # netconf default port is 830, but if ssh works, use 22
    username: str
    passwd: str
    upgrade_image: str
    order: int          # order to iterate through the devices


class DeviceUpgrade():
    ''' Class to drive the device upgrade '''

    def __init__(self, config_file, basic_tests, pre_tests, post1_tests, post2_tests):
        self.device_list = []
        self.upgraded = []
        self.test_summary = {"Pass": 0,
                             "Fail": 0}
        self.js = SnapAdmin()
        self.config = config_file
        self.basic_sanity = basic_tests
        self.pre_sanity = pre_tests
        self.post1_sanity = post1_tests
        self.post2_sanity = post2_tests

    def parse_device_list(self, file_name):
        ''' Parse all the devices from the device file '''
        if prompt_mode:
            self.basic_prompt()
        self.banner("Parse all devices in {0}".format(file_name))
        # Check if this file exists
        if not Path(file_name).is_file():
            return False

        # assume parameter attributes are correct
        with open(file_name) as f:
            try:
                data = yaml.safe_load(f)  # check for valid yml format
            except yaml.YAMLError as e:
                logger.critical("Not a valid yaml format \
                    ({}). Exiting".format(e))
                sys.exit(1)
        for entry in data:
            d = Device(**data[entry])  # order of attributes matters
            self.device_list.append(d)

        # Sort by the order defined in the file
        self.device_list.sort(key=lambda x: x.order)
        for d in self.device_list:
            logger.info(d)
        return True

    def copy_images(self, no_copy):
        ''' Copy all images to devices '''
        if prompt_mode:
            self.basic_prompt()
        if no_copy:
            logger.info("skip copy stage")
            return
        self.banner("Copy upgrade image to all devices")
        if test_mode:
            logger.info("Test mode, skip copy of images")
            return
        # Copy image to /var/tmp since install will pull from there
        for device in self.device_list:
            # Check if file is already on the remote side
            try:
                with StartShell(jdevice(host=device.ip, user=device.username,
                                        password=device.passwd, port=device.port,
                                        normalize=True)) as ss:
                    image = device.upgrade_image.split('/')[-1]
                    # Simple check if file exists and number of bytes
                    # Don't need to generate checksum since we cannot be sure
                    # the same checksum binary is on host and remote
                    cmd = "test -f /var/tmp/{} && echo present || echo missing".format(
                        image)
                    ret, exists = ss.run(cmd)
                    # skip the first line since it is the command"
                    # file exists skip transfer
                    if "present" in exists.splitlines()[1:]:
                        try:
                            num_bytes = ["wc", "-c", device.upgrade_image]
                            local_size = int(
                                subprocess.check_output(num_bytes).split()[0])
                            logger.info(
                                "local image size: {}".format(local_size))
                            ret, remote_size = ss.run(
                                "wc -c /var/tmp/{}".format(image) + str(" | awk '{ print $1 }'"))
                            logger.info("remote image size: {}".format(
                                remote_size.splitlines()[2]))
                            if local_size == int(remote_size.splitlines()[2]):
                                logger.info(
                                    "File already exists, skip image copy for {}".format(device.name))
                                continue
                            else:
                                logger.info(
                                    "File exists, but number of bytes is different, quitting.")
                                sys.exit(1)
                        except Exception as err:
                            logger.warning(
                                "Could not compute file size ({})".format(err))
            except Exception as err:
                logger.warning(
                    "Could not check for file existance,({})".format(err))

            try:
                logger.info("Copying {} to {}".format(
                    device.upgrade_image, device.name))
                cmd = " ".join([splitcopy_path, device.upgrade_image, device.username +
                                "@" + device.ip + ":/var/tmp", "--pwd", device.passwd])
                process = subprocess.Popen(cmd, shell=True)
                process.wait()
                if process.returncode != 0:
                    logger.critical("Image copy not all successful, exiting")
                    sys.exit(1)
                else:
                    logger.info("Image copy successful")
            except Exception as err:
                logger.info(
                    "Issues copying image to {}.  err: {}".format(device.name, err))
                sys.exit(1)

    def is_reachable(self):
        ''' Check basic connectivity '''
        for device in self.device_list:
            try:
                with jdevice(host=device.ip, user=device.username,
                             password=device.passwd, port=device.port,
                             normalize=True) as dev:
                    dev.open()
            except ConnectError as err:
                logger.critical(
                    "Cannot communicate with device({})".format(err))
                return False
        return True

    def basic_device_sanity(self):
        ''' Check that each device passes the basic test case '''
        if prompt_mode:
            self.basic_prompt()

        self.banner("Checking basic sanity on all devices")

        all_pass = True
        check_files = self.basic_sanity
        config_file = self.config

        for device in self.device_list:
            for check in check_files:
                self.write_config(device, config_file, check)
                chk = self.js.snapcheck(config_file, "basic")
                for result in chk:
                    self.increment_results(result.no_passed, result.no_failed)
                    if result.no_failed > 0:
                        all_pass = False
        if not all_pass and prompt_mode:
            ready = None
            logger.info("Not all devices passed the basic sanity check.")
            while ready not in ['c', 'q']:
                ready = input(
                    "(c)ontinue to next test or (q)uit [c/q] ")
                if ready == 'c':
                    ready = 'c'
                    all_pass = True
                    logger.warning("Continue anyways, forced pass")
                elif ready == 'q':
                    all_pass = False
        return all_pass

    def increment_results(self, p, f):
        self.test_summary["Pass"] += p
        self.test_summary["Fail"] += f

    def add_srg1_checks(self):
        ''' add SRG1 checks '''
        self.banner("Verify SRG1 is configured")
        # devices should identical SRG configurations
        device = self.device_list[0]
        with jdevice(host=device.ip, user=device.username,
                     password=device.passwd, port=device.port,
                     normalize=True) as dev:
            sw = SW(dev)
            try:
                reply = sw.rpc.get_chassis_high_availability_srg_information(
                    services_redundancy_group_id='1')
                # check if exception is thrown
                if reply.xpath(".//message")[0].text == "no such SRG is configured":
                    logger.info("NOT configured")
            except Exception:
                logger.info("SRG1 configured")
                self.pre_sanity.append('ha-srg1-checks.yml')
            else:
                logger.info("SRG1 is not configured")

    def add_routing_checks(self):
        ''' add tests for specific protocols '''
        self.banner("Verify protocols")
        protocols = set()

        # devices should all run the same protocol so check the first one
        device = self.device_list[0]
        with jdevice(host=device.ip, user=device.username,
                     password=device.passwd, port=device.port,
                     normalize=True) as dev:
            sw = SW(dev)

            # check if BGP is running
            reply = sw.rpc.get_bgp_summary_information()
            if reply.text is None:
                logger.info("BGP found, add bpg.yml to checks")
                protocols.add("bgp.yml")
            elif "BGP is not running" in reply.text:
                logger.info("BGP is not running")

            # check if OSPF is running
            reply = sw.rpc.get_ospf_neighbor_information()
            if reply.text is None:
                logger.info("OSPF found, add ospf.yml to checks")
                protocols.add("ospf.yml")
            elif "OSPF instance is not running" in reply.text:
                logger.info("OSPF is not running")

            # check if ISIS is running
            reply = sw.rpc.get_isis_adjacency_information()
            if reply.text is None:
                logger.info("ISIS found, add isis.yml to checks")
                protocols.add("isis.yml")
            elif "IS-IS instance is not running" in reply.text:
                logger.info("ISIS is not running")

        # Found protocols need to be checked before and immediately
        # after upgrades before leaving upgrade state
        for proto in protocols:
            self.pre_sanity.append(proto)
            self.post1_sanity.append(proto)

    def write_config(self, device, config_file, test_file):
        '''
        Write the yml file that jsnap will use

        This file needs to be written everytime a new device or test file is used
        '''
        template = {'hosts': [{'device': device.ip,
                               'username': device.username,
                               'passwd': device.passwd,
                               'port': device.port}],
                    'tests': [test_file]}
        with open(config_file, 'w') as outfile:
            yaml.dump(template, outfile, default_flow_style=False)

    def is_vmhost(self, sw):
        ''' check if device is using vmhost architecture '''
        fail_words = ['unknown', 'exception', 'unable']
        try:
            output = sw.rpc.get_vmhost_version_information(
                {'format': 'text'}, ignore_warning=False)
            if any(x in output.text for x in fail_words):
                raise ValueError('Fail word found in output of vmhost check')
        except Exception:
            return False
        return True

    def install_img(self, device):
        ''' Install image on device '''
        image = device.upgrade_image.split('/')[-1]
        self.banner("Installing new image {} on {}".format(image, device.name))

        if test_mode:
            logger.info("Test mode is True, skip install")
            utils.basic_wait("Skip install", 10, cursor)
        else:
            with jdevice(host=device.ip, user=device.username,
                         password=device.passwd, port=device.port,
                         normalize=True) as dev:
                sw = SW(dev)
                logger.info("Use {} install command".format(
                    "vmhost" if self.is_vmhost(sw) else "system"))
                # image should already be copied to device /var/tmp
                ok, msg = sw.install(package=image, validate=False,
                                     no_copy=True, all_re=False,
                                     vmhost=self.is_vmhost(sw),
                                     progress=self.myprogress)
                if ok:
                    logger.info(
                        "install done, will reboot and come up with new image")
                    self.upgraded.append(device)
                    self.reboot_device(sw)
                else:
                    print("Install failed, exiting ({})".format(msg))
                    sys.exit(1)
        logger.info("Install complete")

    def reboot_device(self, sw):
        ''' Reboot device '''
        if self.is_vmhost(sw):
            # ignore warning since RPC exceptions are raised for reboot
            sw.rpc.request_vmhost_reboot(ignore_warning=True)
        else:
            sw.rpc.request_reboot(ignore_warning=True)

    def abort(self):
        ''' Steps to execute on all devices when script aborts '''
        if self.upgraded:
            for device in self.upgraded:
                choice = None
                while choice not in ['y']:
                    choice = input(
                        "Do you want to roll back {}? [y/n] ".format(device.name))
                    if choice == 'y':
                        try:
                            with jdevice(host=device.ip, user=device.username,
                                         password=device.passwd,
                                         port=device.port,
                                         normalize=True, auto_probe=30) as dev:
                                sw = SW(dev)
                                logger.info(
                                    "Rolling back {}.".format(device.name))
                                sw.rpc.request_vmhost_package_rollback() if self.is_vmhost(
                                    sw) else sw.rpc.request_package_rollback()
                                print(
                                    "Roll back complete, rebooting. \
                                    Please manually remove local upgrade state.")
                                self.reboot_device(sw)
                        except Exception as err:
                            logger.info(
                                "Could not execute abort command, {}".format(err))
                    elif choice == 'n':
                        logger.info("Do not rollback {}".format(device.name))
                        break
        else:
            logger.info("No devices were upgraded. Nothing to roll back")
        logger.info("Finished with abort logic")

    def is_online(self, device, timeout):
        ''' Check if device is reachable '''
        if test_mode:
            pass
        # device just rebooted, give 30s buffer before checking status
        utils.basic_wait("Device rebooted", 30, cursor)
        i = 0
        # 45 * 60s per attempt
        while i < timeout:
            try:
                with jdevice(host=device.ip, user=device.username,
                             password=device.passwd, port=device.port,
                             normalize=True,
                             auto_probe=60) as dev:
                    dev.open()
                    if dev.connected:
                        logger.info("Connected to {}".format(device.name))
                        logger.info("Wait for device to initialize")
                        if not test_mode:
                            utils.basic_wait(
                                "Allow device to initialize", post_reboot_wait, cursor)
                        break
            except Exception:
                logger.info(
                    "Not connected yet to device yet. \
                    Retry(#{}) at {}".format(i, datetime.now()))
            i += 1
        else:  # should not get here.
            logger.critical("Device not reachable after timeout, exiting.")
            sys.exit(1)

    def is_img_installed(self, device):
        ''' Verify the upgrade image is installed '''
        if prompt_mode:
            self.basic_prompt()

        image = device.upgrade_image.split('/')[-1]
        self.banner("Verify image {} installed on {}".format(
            image, device.name))

        with jdevice(host=device.ip, user=device.username,
                     password=device.passwd, port=device.port,
                     normalize=True) as dev:
            sw = SW(dev)
            reply = sw.rpc.get_system_information()
            if reply.find('.//os-version').text in image:
                logger.info("OS version matched upgrade image")
            else:
                logger.error(
                    "Possible issues with install, please pause at next phase and verify manually")
                # directly exit, no point to continue
                if not prompt_mode:
                    sys.exit(1)

    def check_all_srg_failover_ready(self, device):
        ''' verify all SRG are ready for failover '''

        if prompt_mode:
            self.basic_prompt()

        self.banner('Checking device for failover ready')

        all_srg_peer_ready = True

        try:
            with jdevice(host=device.ip, user=device.username,
                         password=device.passwd, port=device.port,
                         normalize=True, auto_probe=30) as dev:
                reply = dev.rpc.get_chassis_high_availability_information()
                logger.info("{} local-id: {}".format(device.name,
                                                     reply.find('.//local-id').text))

                for srg, my_role, peer_id, peer_role, failover_ready in zip(reply.findall('.//srg-id'),
                                                                            reply.findall(
                                                                                './/node-role'),
                                                                            reply.findall(
                                                                                './/peer-id'), reply.findall('.//peer-node-role'),
                                                                            reply.findall('.//failover-readiness')):
                    print("SRG: " + srg.text, "-->", "My role: " +
                          my_role.text, "Peer role: " + peer_role.text)
                    if my_role.text == 'ACTIVE':
                        if failover_ready.text == 'READY':
                            logger.info(
                                "Peer is ready for failover for SRG: {}".format(srg.text))
                        else:
                            logger.warning(
                                "Peer({}) is not failover ready yet ({})".format(peer_id.text, failover_ready.text))
                            all_srg_peer_ready = False
                            # do not prompt to retry, just exit
                            if not prompt_mode:
                                sys.exit(1)
                    else:
                        logger.info(
                            "Do nothing for SRG-{} since I am {}".format(srg.text, my_role.text))

        except Exception as err:
            logger.info("Failed to execute RPC ({})".format(err))

        if not all_srg_peer_ready:
            choice = None
            while choice not in ['a', 'c']:
                choice = input(
                    "Not all SRG peers are ready for failover. (a)bort or (c)ontinue anyways: ")
                if choice == 'a':
                    self.abort()
                    sys.exit(0)
                elif choice == 'c':
                    logger.warning("Continue anyways")
                    break
                else:
                    choice = None
        else:
            logger.info("All SRG failover ready")

    def upgrade(self):
        '''
        Upgrade all devices
        For each device:
            Do pre_upgrade sanity, upgrade, then post_upgrade sanity
            before moving onto the next device.
        '''
        if prompt_mode:
            self.basic_prompt()

        for device in self.device_list:
            # confirm if we should skip this device upgrade
            if prompt_mode:
                skip = input(
                    "Skip upgrading this device ({})? [y/n] ".format(device.name))
                if skip == 'y':
                    confirm = input(
                        "Confirm skip upgrade of device ({})? [y/n] ".format(device.name))
                    if confirm == 'y':
                        continue
            self.pre_upgrade_validation(device)
            self.check_all_srg_failover_ready(device)
            self.config_software_upgrade(device)
            self.install_img(device)
            self.is_online(device, 45)
            self.is_img_installed(device)
            self.post1_upgrade_validation(device)
            self.delete_software_upgrade(device)
            self.post2_upgrade_validation(device)
            logger.info("Done with upgrade for {}".format(device))
            utils.basic_wait("Wait 30 seconds before next device", 30, cursor)
        logger.info("Done with all devices")

    def pre_upgrade_validation(self, device):
        ''' Run pre upgrade on specificed device '''

        self.banner(
            "Gathering PRE upgrade information for {}".format(device.name))

        # pre-check sanity files
        check_files = self.pre_sanity
        # file jsnap uses run tests
        config_file = self.config

        for check in check_files:
            logger.info("Gathering information for {}".format(check))
            # must write the jsnap config file before running a new test
            self.write_config(device, config_file, check)
            # take snapshot and save it to the snapshot directory in xml format
            self.js.snap(config_file, "pre")

    def config_software_upgrade(self, device):
        ''' configure software upgrade mode so that after install, it boots into offline '''
        if prompt_mode:
            self.basic_prompt()

        self.banner(
            "Configure software upgrade upon boot for {}".format(device.name))

        if test_mode:
            logger.info("Test mode is True, skip configure")
            return

        try:
            with jdevice(host=device.ip, user=device.username,
                         password=device.passwd, port=device.port,
                         normalize=True) as dev:
                cu = Config(dev)
                config_text = "set chassis high-availability software-upgrade"
                cu.load(config_text, format="set", merge=True)
                cu.commit(timeout=300)
                logger.info("Commit({}) done".format(config_text))
        except Exception as err:
            logger.critical(
                "Unable to configure software-upgrade, exiting. ({})".format(err))

        time.sleep(5)
        # Ensure SRG0 is Offline now
        try:
            with jdevice(host=device.ip, user=device.username,
                         password=device.passwd, port=device.port,
                         normalize=True, auto_probe=30) as dev:
                sw = SW(dev)
                reply = sw.rpc.get_chassis_high_availability_information()
                if reply.xpath(".//node-status")[0].text != "OFFLINE [ SU ]":
                    logger.critical("OFFLINE [ SU ] Not found, exiting")
                    sys.exit(1)
        except Exception:
            logger.critical("Could not verify node status")

    def delete_software_upgrade(self, device):
        ''' remove software upgrade mode so the device can probe for activeness '''
        if prompt_mode:
            self.basic_prompt()

        self.banner(
            "Remove configuration software upgrade for {}".format(device.name))

        if test_mode:
            logger.info("Test mode is True, skip delete configure")
            return

        try:
            with jdevice(host=device.ip, user=device.username,
                         password=device.passwd, port=device.port,
                         normalize=True) as dev:
                cu = Config(dev)
                config_text = "delete chassis high-availability software-upgrade"
                cu.load(config_text, format="set", merge=True)
                cu.commit(timeout=300)
                logger.info("Commit({}) done".format(config_text))
        except Exception as err:
            logger.critical(
                "Unable to delete software-upgrade, exiting. ({})".format(err))

        time.sleep(5)

        # Ensure SRG0 is Online now
        try:
            with jdevice(host=device.ip, user=device.username,
                         password=device.passwd, port=device.port,
                         normalize=True, auto_probe=30) as dev:
                sw = SW(dev)
                reply = sw.rpc.get_chassis_high_availability_information()
                if reply.xpath(".//node-status")[0].text != "ONLINE":
                    logger.critical("OFFLINE Not found, exiting")
                    sys.exit(1)
        except Exception:
            logger.critical("Could not verify node status")

    def post2_upgrade_validation(self, device):
        ''' Run post2 upgrade on specified device '''
        # always prompt here, the testbed just booted up and needs time
        # to initialize or many RPC commands will fail
        utils.basic_wait("Allow RE to settle before collecting post2 \
            information. Wait {} seconds".format(
            delete_config_wait), delete_config_wait, cursor)

        self.banner(
            "Gather POST2 upgrade information for {}".format(device.name))

        check_files = self.post2_sanity
        config_file = self.config

        for check in check_files:
            ready = None  # if not ready, do not move onto next test
            self.write_config(device, config_file, check)
            while ready not in ['c']:
                logger.info("Gathering information for {}".format(check))
                try:
                    chk = self.js.snap(config_file, "post")

                    logger.info("Compare pre and post")
                    chk = self.js.check(config_file, "pre", "post")
                except Exception as e:
                    logger.info(
                        "Its possible CLIs will fail becuase the device\
                        is still boot (ie, fpc still coming online, \
                        please redo test")
                    logger.info(e)
                for ch in chk:
                    self.increment_results(ch.no_passed, ch.no_failed)
                if prompt_mode is False:
                    ready = 'c'
                else:
                    ready = input(
                        "(c)ontinue to next test, (r)edo, or (a)bort [c/r/a] ")
                if ready == 'r':
                    logger.info("Redo current test")
                elif ready == 'a':
                    logger.critical(
                        "User abort (add roll back later, for now just quit program")
                    self.abort()
                    sys.exit(0)

    def post1_upgrade_validation(self, device):
        ''' Run post1 upgrade on specified device '''
        if prompt_mode:
            self.basic_prompt("Post validation phase 1.")

        self.banner(
            "Do POST1 checks before removing local upgrade config for {}".format(device.name))

        check_files = self.post1_sanity
        config_file = self.config

        for check in check_files:
            ready = None  # if not ready, do not move onto next test
            self.write_config(device, config_file, check)
            while ready not in ['c']:
                logger.info("Gathering information for {}".format(check))
                try:
                    chk = self.js.snap(config_file, "post")

                    logger.info("Compare pre and post")
                    chk = self.js.check(config_file, "pre", "post")
                except Exception as e:
                    logger.info(
                        "Try again, device is probably not ready ({})".format(e))
                for ch in chk:
                    self.increment_results(ch.no_passed, ch.no_failed)
                if prompt_mode:
                    ready = input(
                        "(c)ontinue to next test, (r)edo, or (a)bort [c/r/a] ")
                else:
                    ready = 'c'
                if ready == 'r':
                    logger.info("Redo current test")
                elif ready == 'a':
                    logger.critical(
                        "User abort, execute rollback logic")
                    self.abort()
                    sys.exit(0)

    def final_summary(self):
        ''' Summary of passed/failed test cases '''
        self.banner("Summary of test case results")
        logger.info("Total test case passed: {}".format(
            self.test_summary["Pass"]))
        logger.info("Total test case failed: {}".format(
            self.test_summary["Fail"]))

    def myprogress(self, dev, report):
        ''' Helper to print status of junos install '''
        print("host: %s, report: %s" % (dev.hostname, report))

    def banner(self, msg):
        ''' Banner to segment console output '''
        logger.info("="*80)
        logger.info(msg.center(80))
        logger.info("="*80)

    def basic_prompt(self, msg=None):
        ''' Wait for user input before continuing '''
        if msg:
            logger.info(msg)
        ready = None
        while ready not in ['y']:
            ready = input("Ready for next step? (y)es, (n)o, (a)bort [y/n/a] ")
            if ready == 'a':
                logger.critical("User aborted")
                self.abort()
                sys.exit(0)


def start(device_file, config_file, basic, pre, post1, post2):
    ''' Entry point '''
    du = DeviceUpgrade(config_file, basic, pre, post1, post2)

    logger.info("Test mode: {}, Prompt mode: {}, No Copy: {}, No Cursor: {}".format(
        test_mode, prompt_mode, no_copy, cursor))

    if du.parse_device_list(device_file) is True:
        logger.info("Device params file parsed")
    else:
        logger.error("Failed to parse device params file")
        sys.exit(1)

    if du.is_reachable() is False:
        logger.error("Not all devices are reachable, exit.")
        sys.exit(1)
    # add SRG1 checks
    # this must happen before basic sanity to SRG1 state can be checked
    du.add_srg1_checks()

    # All devices need to pass basic sanity or we should not proceed
    if du.basic_device_sanity() is True:
        logger.info("All devices passed basic sanity.")
    else:
        logger.error("Not all devices passed basic sanity, please check.")
        du.final_summary()
        # comment out for testing purposes
        sys.exit(1)

    # add protocol specific checks
    du.add_routing_checks()

    # comment out for testing purposes
    du.copy_images(no_copy)

    logger.info("Start upgrading each device 1 at a time.")
    du.upgrade()

    # show total test case pass/fail
    du.final_summary()

    sys.exit(0)


if __name__ == "__main__":
    # suppress logging noise
    logging.getLogger("ncclient.transport.ssh").setLevel(logging.WARNING)
    logging.getLogger("ncclient.operations.rpc").setLevel(logging.WARNING)
    logging.getLogger("jnpr.jsnapy.check").setLevel(logging.WARNING)
    logger = logging.getLogger(__name__)

    # create snapshot directory
    Path("snapshots").mkdir(parents=True, exist_ok=True)

    # required: set custom jsnapy path
    os.environ["JSNAPY_HOME"] = "./.jsnapy/"

    # quit if splitcopy is not in PATH
    splitcopy_path = shutil.which('splitcopy')
    if splitcopy_path is None:
        logger.critical("Splitcopy not found in PATH, exiting.")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    required = parser.add_argument_group('required named arguments')
    required.add_argument(
        "--params",
        help="YML formatted parameter file containing device information",
        required=True)
    parser.add_argument(
        "--test_run", help="Do not execute actions that affect device state",
        action="store_true")
    parser.add_argument(
        "--prompt", help="Query for user input at each phase",
        action="store_true")
    parser.add_argument(
        "--no_copy", help="Do not copy image to device",
        action="store_true")
    parser.add_argument(
        "--no_cursor", help="Do not reposition cursor",
        action="store_true")
    args = parser.parse_args()

    test_mode = args.test_run
    prompt_mode = args.prompt
    params_file = args.params
    no_copy = args.no_copy
    cursor = args.no_cursor

    config = configparser.ConfigParser()
    config.read('.jsnapy/timers.cfg')
    timers = config['DEFAULT']
    # default to 30 mins
    post_reboot_wait = int(timers['post_reboot_wait'])
    # default to 10 mins
    delete_config_wait = int(timers['delete_config_wait'])

    # basic sanity executed before any upgrades
    basic = ["basic-checks.yml", "ha-checks.yml"]

    # Metrics collected to be compared before and after device software upgrade
    # post1 is used to ensure basic components are available
    # post2 is comprehensive
    pre = post2 = ["device-checks.yml", "fpc-checks.yml",
                   "interface-checks.yml", "routing.yml",
                   "basic-ha-checks.yml", "ha-checks.yml",
                   "bfd.yml"]
    post1 = ["basic-ha-checks.yml", "fpc-checks.yml", "bfd.yml"]

    # device.yml - default file.
    # Will be rewritten everytime a new tests is performed
    start(params_file, "device.yml", basic, pre, post1, post2)
