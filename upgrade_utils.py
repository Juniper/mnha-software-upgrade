import time
import logging
import yaml

from prompt_toolkit import HTML
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import ProgressBar
import doUpgrade

logger = logging.getLogger(__name__)


def basic_wait(msg, seconds, no_cursor):

    # simply sleep if terminal doesn't support cursor repositioning
    # as this will cause unreadable output
    if no_cursor:
        logger.info("Waiting {} seconds".format(seconds))
        time.sleep(seconds)
        return

    bottom_toolbar = HTML(
        '<b>[s]</b> Skip wait and continue'
    )

    # Create custom key bindings first.
    kb = KeyBindings()
    cancel = [False]

    @kb.add("s")
    def _(event):
        # break out of loop
        cancel[0] = True

    # Use `patch_stdout`, to make sure that prints go above the
    # application.
    with patch_stdout():
        with ProgressBar(title="{} (Waiting {}s)".format(msg, str(seconds)),
                         key_bindings=kb, bottom_toolbar=bottom_toolbar) as pb:
            for i in pb(range(seconds)):
                time.sleep(1)

                if cancel[0]:
                    break

def write_device_list_helper(target_file, device1, device2):
    ''' generate device list file '''
    template = {'srx_1': {'name': device1.name,
                           'ip': device1.ip,
                           'port': device1.port,
                           'username': device1.username,
                           'order': device1.order,
                           'passwd': device1.passwd,
                           'upgrade_image': device1.upgrade_image},
                'srx_2': {'name': device2.name,
                           'ip': device2.ip,
                           'port': device2.port,
                           'username': device2.username,
                           'order': device2.order,
                           'passwd': device2.passwd,
                           'upgrade_image': device2.upgrade_image}}
    with open(target_file, 'w') as outfile:
        yaml.dump(template, outfile, default_flow_style=False)

if __name__ == "__main__":
    dev1 = doUpgrade.Device("node0", "5.6.7.8", 22, "admin", "pass", "/path/to/image.tgz", 1)
    dev2 = doUpgrade.Device("node1", "5.6.7.9", 22, "admin", "pass", "/path/to/image.tgz", 2)
    write_device_list_helper("test_device_list.yml", dev1, dev2)
    #basic_wait("test", 10, True)
    #basic_wait("test", 10, False)
