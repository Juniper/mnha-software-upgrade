# mnha-software-upgrade

## Abstract
This off box utility assists in the software upgrade of SRX MultiNode High Availability deployments.

## Installation
Requires Python >= 3.7 and associated pip tool.

python3.7 -m pip install -r requirements.txt

## File Structure
.jsnapy                   -> Contains configurations
LICENSE
NOTICES.txt
README
device_list_example.yml.  -> Example params file
doUpgrade.py              -> Entry point
requirements.txt          -> Dependencies
testfiles                 -> Contains all test yml files
upgrade_utils.py

## Logging
Upgrade logs will be written in "upgrade.log" in the same directory as the script.

## Basic overview of the software upgrade procedure
1) Parse passed in device yml file.
2) Execute basic device sanity.
3) Copy image to all devices.
4) Upgrade deployment.
4.1) Gather metrics before upgrade.
4.2) Verify peer is ready for failover.
4.3) Configure software upgrade state.
4.4) Install image and reboot device.
4.5) Verify intended image is installed.
4.6) Validate metrics from before upgrade.
4.7) Remove software upgrade configuration.
5) Upgrade next devices.
6) Summary


## Usage
python3.7 doUpgrade.py --help
usage: doUpgrade.py [-h] --params PARAMS [--test_run] [--prompt] [--no_copy] [--no_cursor]

optional arguments:
  -h, --help       show this help message and exit
  --test_run       Do not execute actions that affect device state
  --prompt         Query for user input at each phase
  --no_copy        Do not copy image to device
  --no_cursor      Do not reposition cursor

required named arguments:
  --params PARAMS  YML formatted parameter file containing device information
  
1) Execute with --test_run and --prompt first to make sure all tests can pass and there are no major complications.
test_run will skip actions that affect device state. With --test_run, information is fetched from the devices and tests are run, but no action is taken. The script will prompt the user at every step due to the --prompt argument.

python3.7 doUpgrade.py --params device_list.yml --test_run
* Images are not copied.
* Image install will not happen.
* Configurations do not occur.
* Use the running image as the upgrade image in the params file so the device so image validation can pass.
* Device states do not change.
 
2) Execute with --test_run with out --prompt to execute through the steps automatically.

3) Perform all actions automatically and upgrade the topology.
python3.7 doUpgrade.py --params device_list.yml

3.1) Prompt the user at every stage and upgrade the topology.
python3.7 doUpgrade.py --params device_list.yml --prompt
