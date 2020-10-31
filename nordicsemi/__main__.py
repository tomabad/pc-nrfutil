#
# Copyright (c) 2016 Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
#   3. Neither the name of Nordic Semiconductor ASA nor the names of other
#   contributors to this software may be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
#   4. This software must only be used in or with a processor manufactured by Nordic
#   Semiconductor ASA, or in or with a processor manufactured by a third party that
#   is used in combination with a processor manufactured by Nordic Semiconductor.
#
#   5. Any software provided in binary or object form under this license must not be
#   reverse engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
import ipaddress
import signal

"""nrfutil command line tool."""
import os
import sys
import click
import time
import logging
import re
sys.path.append(os.getcwd())

#from nordicsemi.dfu.dfu import Dfu
from nordicsemi.dfu.dfu_transport import DfuEvent, TRANSPORT_LOGGING_LEVEL
#from nordicsemi.dfu.dfu_transport_serial import DfuTransportSerial
#from nordicsemi.dfu.package import Package
from nordicsemi import version as nrfutil_version
#from nordicsemi.dfu.signing import Signing
#from nordicsemi.dfu.util import query_func
from nordicsemi.zigbee.prod_config import ProductionConfig, ProductionConfigWrongException, ProductionConfigTooLargeException
#from pc_ble_driver_py.exceptions import NordicSemiException
from nordicsemi.lister.device_lister import DeviceLister
import spinel.util as util

logger = logging.getLogger(__name__)

def ble_driver_init(conn_ic_id):
    global DfuTransportBle

def display_sec_warning():
    default_key_warning = """
|===============================================================|
|##      ##    ###    ########  ##    ## #### ##    ##  ######  |
|##  ##  ##   ## ##   ##     ## ###   ##  ##  ###   ## ##    ## |
|##  ##  ##  ##   ##  ##     ## ####  ##  ##  ####  ## ##       |
|##  ##  ## ##     ## ########  ## ## ##  ##  ## ## ## ##   ####|
|##  ##  ## ######### ##   ##   ##  ####  ##  ##  #### ##    ## |
|##  ##  ## ##     ## ##    ##  ##   ###  ##  ##   ### ##    ## |
| ###  ###  ##     ## ##     ## ##    ## #### ##    ##  ######  |
|===============================================================|
|The security key you provided is insecure, as it part of a     |
|known set of keys that have been widely distributed. Do NOT use|
|it in your final product or your DFU procedure may be          |
|compromised and at risk of malicious attacks.                  |
|===============================================================|
"""
    click.echo("{}".format(default_key_warning))

def display_nokey_warning():
    default_nokey_warning = """
|===============================================================|
|##      ##    ###    ########  ##    ## #### ##    ##  ######  |
|##  ##  ##   ## ##   ##     ## ###   ##  ##  ###   ## ##    ## |
|##  ##  ##  ##   ##  ##     ## ####  ##  ##  ####  ## ##       |
|##  ##  ## ##     ## ########  ## ## ##  ##  ## ## ## ##   ####|
|##  ##  ## ######### ##   ##   ##  ####  ##  ##  #### ##    ## |
|##  ##  ## ##     ## ##    ##  ##   ###  ##  ##   ### ##    ## |
| ###  ###  ##     ## ##     ## ##    ## #### ##    ##  ######  |
|===============================================================|
|You are not providing a signature key, which means the DFU     |
|files will not be signed, and are vulnerable to tampering.     |
|This is only compatible with a signature-less bootloader and is|
|not suitable for production environments.                      |
|===============================================================|
"""
    click.echo("{}".format(default_nokey_warning))

def display_debug_warning():
    debug_warning = """
|===============================================================|
|##      ##    ###    ########  ##    ## #### ##    ##  ######  |
|##  ##  ##   ## ##   ##     ## ###   ##  ##  ###   ## ##    ## |
|##  ##  ##  ##   ##  ##     ## ####  ##  ##  ####  ## ##       |
|##  ##  ## ##     ## ########  ## ## ##  ##  ## ## ## ##   ####|
|##  ##  ## ######### ##   ##   ##  ####  ##  ##  #### ##    ## |
|##  ##  ## ##     ## ##    ##  ##   ###  ##  ##   ### ##    ## |
| ###  ###  ##     ## ##     ## ##    ## #### ##    ##  ######  |
|===============================================================|
|You are generating a package with the debug bit enabled in the |
|init packet. This is only compatible with a debug bootloader   |
|and is not suitable for production.                            |
|===============================================================|
"""
    click.echo("{}".format(debug_warning))

def display_settings_backup_warning():
    debug_warning = """
Note: Generating a DFU settings page with backup page included.
This is only required for bootloaders from nRF5 SDK 15.1 and newer.
If you want to skip backup page generation, use --no-backup option."""
    click.echo("{}".format(debug_warning))

def int_as_text_to_int(value):
    try:
        if value[:2].lower() == '0x':
            return int(value[2:], 16)
        elif value[:1] == '0':
            return int(value, 8)
        return int(value, 10)
    except ValueError:
        raise NordicSemiException('%s is not a valid integer' % value)

def pause():
    while True:
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            break

class BasedIntOrNoneParamType(click.ParamType):
    name = 'Integer'

    def convert(self, value, param, ctx):
        try:
            if value.lower() == 'none':
                return 'none'
            return int_as_text_to_int(value)
        except NordicSemiException:
            self.fail('%s is not a valid integer' % value, param, ctx)

BASED_INT_OR_NONE = BasedIntOrNoneParamType()

class BasedIntParamType(BasedIntOrNoneParamType):
    name = 'Integer'

BASED_INT = BasedIntParamType()

class TextOrNoneParamType(click.ParamType):
    name = 'Text'

    def convert(self, value, param, ctx):
        return value

TEXT_OR_NONE = TextOrNoneParamType()

BOOT_VALIDATION_ARGS = [
    'NO_VALIDATION',
    'VALIDATE_GENERATED_CRC',
    'VALIDATE_GENERATED_SHA256',
    'VALIDATE_ECDSA_P256_SHA256',
]
DEFAULT_BOOT_VALIDATION = 'VALIDATE_GENERATED_CRC'

KEY_CHOICE = ['pk', 'sk']
KEY_FORMAT = [
    'hex',
    'code',
    'pem',
    'dbgcode',
]


class OptionRequiredIf(click.Option):

    def full_process_value(self, ctx, value):
        value = super().full_process_value(ctx, value)
        if ('serial_number' not in ctx.params or not ctx.params['serial_number']) and value is None:
            msg = 'Required if "-snr" / "--serial-number" is not defined.'
            raise click.MissingParameter(ctx=ctx, param=self, message=msg)
        return value

@click.group()
@click.option('-v', '--verbose',
              help='Increase verbosity of output. Can be specified more than once (up to -v -v -v -v).',
              count=True)
@click.option('-o', '--output',
              help='Log output to file',
              metavar='<filename>')
def cli(verbose, output):
    #click.echo('verbosity: %s' % verbose)
    if verbose == 0:
        log_level = logging.ERROR
    elif verbose == 1:
        log_level = logging.WARNING
    elif verbose == 2:
        log_level = logging.INFO
    elif verbose == 3:
        log_level = logging.DEBUG
    else:
        # Custom level, logs all the bytes sent/received over the wire/air
        log_level = TRANSPORT_LOGGING_LEVEL

    logging.basicConfig(format='%(asctime)s %(message)s', level=log_level)

    if (output):
        root = logging.getLogger('')
        fh = logging.FileHandler(output)
        fh.setLevel(log_level)
        fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        root.addHandler(fh)

@cli.command()
def version():
    """Display nrfutil version."""
    click.echo("nrfutil version {}".format(nrfutil_version.NRFUTIL_VERSION))
    logger.info("PyPi URL: https://pypi.python.org/pypi/nrfutil")
    logger.debug("GitHub URL: https://github.com/NordicSemiconductor/pc-nrfutil")

@cli.group(short_help='Generate and display Bootloader DFU settings.')
def settings():
    """
    This set of commands supports creating and displaying bootloader settings.
    """
    pass

@cli.group(short_help='Perform a Device Firmware Update over serial, BLE, Thread, Zigbee or ANT transport given a DFU package (zip file).')
def dfu():
    """
    This set of commands supports Device Firmware Upgrade procedures over both BLE and serial transports.
    """
    pass
@dfu.command(short_help="Update the firmware on a device over a Thread connection.")
@click.option('-pkg', '--package',
              help='Filename of the DFU package.',
              type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=False),
              required=True)
@click.option('-p', '--port',
              help='Serial port COM port to which the NCP is connected.',
              type=click.STRING)
@click.option('-a', '--address',
              help='Device IPv6 address. If address is not specified then perform DFU '
                   'on all capable devices. If multicast address is specified (FF03::1), '
                   'perform multicast DFU.',
              type=click.STRING)
@click.option('-sp', '--server_port',
              help='UDP port to which the DFU server binds. If not specified the 5683 is used.',
              type=click.INT,
              default=5683)
@click.option('--panid',
              help='802.15.4 PAN ID. If not specified then 1234 is used as PAN ID.',
              type=click.INT)
@click.option('--channel',
              help='802.15.4 Channel. If not specified then channel 11 is used.',
              type=click.INT)
@click.option('-snr', '--jlink_snr',
              help='Jlink serial number.',
              type=click.STRING)
@click.option('-f', '--flash_connectivity',
              help='Flash NCP connectivity firmware automatically. Default: disabled.',
              type=click.BOOL,
              is_flag=True)
@click.option('-s', '--sim',
              help='Use software NCP and connect to the OT simulator.',
              type=click.BOOL,
              is_flag=True)
@click.option('-r', '--rate',
              help="Multicast upload rate in blocks per second.",
              type=click.FLOAT)
@click.option('-rs', '--reset_suppress',
              help='Suppress device reset after finishing DFU for a given number of milliseconds. ' +
                   'If -1 is given then suppress indefinatelly.',
              type = click.INT,
              metavar = '<delay_in_ms>')
@click.option('-m', '--masterkey',
              help='Masterkey. If not specified then 00112233445566778899aabbccddeeff is used',
              type=click.STRING)

def thread(package, port, address, server_port, panid, channel, jlink_snr, flash_connectivity,
           sim, rate, reset_suppress, masterkey):
    """
    Perform a Device Firmware Update on a device that supports Thread DFU.
    This requires a second nRF device, connected to this computer, with Thread Network
    CoProcessor (NCP) firmware loaded. The NCP device will perform the DFU procedure onto
    the target device.
    """
    ble_driver_init('NRF52')
    from nordicsemi.thread import tncp
    from nordicsemi.thread.dfu_thread import create_dfu_server
    from nordicsemi.thread.tncp import NCPTransport

    mcast_dfu = False

    if address is None:
        address = ipaddress.ip_address("ff03::1")
        click.echo("Address not specified. Using ff03::1 (all Thread nodes)")
    else:
        try:
            address = ipaddress.ip_address(address)
            mcast_dfu = address.is_multicast
        except:
            click.echo("Invalid IPv6 address")
            return 1

    if (not sim):
        if port is None and jlink_snr is None:
            click.echo("Please specify serial port or Jlink serial number.")
            return 2

        elif port is None:
            port = get_port_by_snr(jlink_snr)
            if port is None:
                click.echo("\nNo Segger USB CDC ports found, please connect your board.")
                return 3

        stream_descriptor = 'u:' + port
        click.echo("Using connectivity board at serial port: {}".format(port))
    else:
        stream_descriptor = 'p:' + Flasher.which('ot-ncp') + ' 30'
        click.echo("Using ot-ncp binary: {}".format(stream_descriptor))


    config = tncp.NCPTransport.get_default_config()
    if (panid):
        config[tncp.NCPTransport.CFG_KEY_PANID] = panid
    if (channel):
        config[tncp.NCPTransport.CFG_KEY_CHANNEL] = channel
    if (masterkey):
        config[tncp.NCPTransport.CFG_KEY_MASTERKEY] = util.hex_to_bytes(masterkey)

    config[tncp.NCPTransport.CFG_KEY_RESET] = False
    opts = type('DFUServerOptions', (object,), {})()
    opts.rate = rate
    opts.reset_suppress = reset_suppress
    opts.mcast_dfu = mcast_dfu

    transport = NCPTransport(server_port, stream_descriptor, config)
    dfu = create_dfu_server(transport, package, opts)

    try:
        sighandler = lambda signum, frame : transport.close()
        signal.signal(signal.SIGINT, sighandler)
        signal.signal(signal.SIGTERM, sighandler)

        transport.open()
        # Delay DFU trigger until NCP promotes to a router (6 seconds by default)
        click.echo("Waiting for NCP to promote to a router...")
        time.sleep(6.0)
        dfu.trigger(address, 3)
        click.echo("Thread DFU server is running... Press <Ctrl + D> to stop.")
        pause()
        click.echo("Terminating")

    except Exception as e:
        logger.exception(e)
    finally:
        transport.close()


if __name__ == '__main__':
    cli()
