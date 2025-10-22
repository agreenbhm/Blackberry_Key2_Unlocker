import time
import usb1
import subprocess
import argparse

# Constants for vendor and product IDs
VENDOR_ID = 0x0fca
PRODUCT_ID = 0x8040

fwver = ''

patch = [ # (address, value) pairs to patch in the abl image
    (0x4152c,0x1f),
    (0x4152d,0x20),
    (0x4152e,0x03),
    (0x4152f,0xd5),
    (0x41530,0x38),
    (0x41531,0x00),
    (0x41532,0xff),
    (0x41533,0x17),
    (0x1cb8,0x08),
    (0x1cb9,0x00),
    (0x1cba,0x80),
    (0x1cbb,0x52),
    (0x1d58,0x13),
    (0x1d59,0x00),
    (0x1d5a,0x80),
    (0x1d5b,0xd2),
    (0x68b68,0x16),
    (0x68b69,0x00),
    (0x68b6a,0x00),
    (0x68b6b,0x14),
    (0x68c30,0x18),
    (0x68c31,0x00),
    (0x68c32,0x00),
    (0x68c33,0x14),
    (0x4880,0x23),
    (0x4881,0x00),
    (0x4882,0x00),
    (0x4883,0x14),
    (0x1db8,0x00),
    (0x1db9,0x00),
    (0x1dba,0x80),
    (0x1dbb,0x52),
    (0x49b8,0x00),
    (0x49b9,0x00),
    (0x49ba,0x80),
    (0x49bb,0xd2),
    (0x13814,0x00),
    (0x13815,0x28),
    (0x13816,0x38),
    (0x13817,0x91),
    (0x1aa8,0x40),
    (0x1aa9,0x00),
    (0x1aaa,0x80),
    (0x1aab,0x52),
    (0x21bfc,0x15),
    (0x21bfd,0x00),
    (0x21bfe,0x80),
    (0x21bff,0x52)
]

def sleep(ms):
    time.sleep(ms / 1000.0)


# Parse command line arguments
parser = argparse.ArgumentParser(description='Blackberry Key2[LE] Unlocker')
parser.add_argument('recovery_image', help='Path to the recovery image file')
parser.add_argument('files_dir', help='Path to the directory containing firmware files')
args = parser.parse_args()

# Open the USB device
context = usb1.USBContext()
device = context.openByVendorIDAndProductID(VENDOR_ID, PRODUCT_ID)

if device is None:
    raise Exception("Device not found")

endpoint_address_write = 0x01
# Endpoint address for bulk read
endpoint_address_read = 0x81

def bulk_transfer(data, readcount=128, timeout=100):
    try:
        # Write the data to the USB device
        written = device.bulkWrite(endpoint_address_write, data, timeout)
        print(f"Data written successfully: {written}")
    except Exception as e:
        print(f"Error writing data: {e}")
    try:
        # Read the response from the USB device in a loop until data is exhausted
        read = b''
        try:
            while True:
                read += device.bulkRead(endpoint_address_read, readcount, timeout) + b'\n'
        except usb1.USBErrorTimeout:
            # Timeout reached or no more data, stop reading
            pass
        results = read.decode('utf-8', errors='replace')
        print(f"Data read successfully:\n\n {results}")
        return results
    except Exception as e:
        print(f"Error reading data: {e}")

def reverse_bytes(data):
    # Accept bytes, bytearray, or a hex string and return reversed bytes
    if isinstance(data, str):
        data = bytes.fromhex(data.replace(' ', ''))
    elif isinstance(data, bytearray):
        data = bytes(data)
    elif not isinstance(data, bytes):
        raise TypeError("Expected bytes, bytearray, or hex string")
    return data[::-1]

# Reverse bytes needed for requesting device info and send to device
device_info = bulk_transfer(reverse_bytes(bytes.fromhex('6f666e69206d656f')))

# Determine firmware version based on device info
if '575' in device_info:
    fwver = '575'
elif '160' in device_info:
    fwver = '160'
else:
    print("Unknown firmware version, exiting.")
    exit(1)

# Send 0x30; unclear purpose
bulk_transfer(bytes.fromhex('30'))
sleep(100)

# Send 1MB of zeros to the device
bulk_transfer(bytes.fromhex('00')*0x100000, timeout=3000)

# Load the appropriate abl firmware file
fwver_path = f'{args.files_dir}/{fwver}' if args.files_dir else fwver
with open(f'{fwver_path}', 'rb') as f:
    payload = f.read()

payload = bytearray(payload)

# Apply patches to the payload
for addr, val in patch:
    payload[addr] = val

# Send the patched payload to the device
bulk_transfer(payload[:0x68c34], timeout=3000)
sleep(500)

device.close()
sleep(100)

# Use fastboot to flash the recovery image
fastboot = subprocess.run(
    ['fastboot', 'flash', 'recovery', args.recovery_image],
    capture_output=True,
    text=True
)
print(fastboot.stdout)

# Use fastboot to boot recovery image by exploiting patched function
fastboot = subprocess.run(
    ['fastboot', 'oem', 'get-flash-status'],
    capture_output=True,
    text=True
)
print(fastboot.stdout)
