### Goal
- The goal is to simulate a basic secure NFC communication between two Raspberry Pi Picos. One Pico (the Reader) acts like an NFC reader, and the other (the Tag) emulates an NFC tag. The communication is secured using the SIMON64/128 block cipher and a simplified HMAC for integrity

- **What is SIMON64/128?**
	- SIMON64/128 is a **lightweight block cipher** developed by **NSA** for resource-constrained devices like **NFC tags, IoT, and embedded systems**. It is part of the **SIMON family**, optimized for high security with minimal computational overhead
	- It uses **Feistel-like** with bitwise shifts, rotations, and XOR operations
### Steps to work
1. Install micropython-pn532 on **both the devices**
```
import mip
 mip.install("github:mcauser/micropython-pn532")
```


2. **Simon.py** (Both the devices)
```python
# simon.py (SIMON64/128 Implementation - MicroPython)

class SimonCipher:
    def __init__(self, key, key_size=128, block_size=64):
        if key_size not in [64, 96, 128, 192, 256]:
            raise ValueError("Invalid key size")
        if block_size not in [32, 48, 64, 96, 128]:
            raise ValueError("Invalid block size")
        self.key_size = key_size
        self.block_size = block_size
        self.rounds = {
            (32, 64): 32, (48, 64): 36, (48, 72): 36,
            (64, 96): 42, (64, 128): 44, (96, 96): 52,
            (96, 144): 54, (128, 128): 68, (128, 192): 69,
            (128, 256): 72
        }[(block_size, key_size)]
        self.key = self.expand_key(key)

    def expand_key(self, key):
        if self.key_size == 128:
            k = [int.from_bytes(key[i:i+4], 'little') for i in range(0, 16, 4)]
            for i in range(4, self.rounds):
                tmp = self.right_rotate(k[i-1], 3)
                if self.key_size == 128:
                    tmp = tmp ^ k[i-3]
                tmp = tmp ^ self.right_rotate(tmp, 1)
                k.append((0xfffffffc ^ k[i-4] ^ tmp) & 0xffffffff)
            return k
        else:
            raise NotImplementedError("Key size other then 128 bit") #error handler

    def right_rotate(self, x, n):
        return (x >> n) | ((x << (32 - n)) & 0xffffffff)

    def left_rotate(self, x, n):
        return ((x << n) & 0xffffffff) | (x >> (32 - n))

    def encrypt_block(self, block):
        x = int.from_bytes(block[0:4], 'little')
        y = int.from_bytes(block[4:8], 'little')

        for i in range(self.rounds):
            tmp = x
            x = (y ^ (self.left_rotate(x, 1) & self.left_rotate(x, 8)) ^ self.left_rotate(x, 2) ^ self.key[i]) & 0xffffffff
            y = tmp

        return x.to_bytes(4, 'little') + y.to_bytes(4, 'little')

    def decrypt_block(self, block):
        x = int.from_bytes(block[0:4], 'little')
        y = int.from_bytes(block[4:8], 'little')

        for i in range(self.rounds - 1, -1, -1):
            tmp = y
            y = (x ^ (self.left_rotate(y, 1) & self.left_rotate(y, 8)) ^ self.left_rotate(y, 2) ^ self.key[i]) & 0xffffffff
            x = tmp
        return x.to_bytes(4, 'little') + y.to_bytes(4, 'little')


# --- Helper Functions ---
def bytes_to_hex(bytes_data):
    return ''.join('{:02x}'.format(x) for x in bytes_data)

def hex_to_bytes(hex_string):
    return bytes(int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2))

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])
```


3. **Installing  pn532.py code from the downloaded module** (On Both the devices)


#### Reader(Pico-1):

```python
# main.py (Pi Pico 1 - READER)
import machine
import time
from pn532 import PN532_SPI
from simon import SimonCipher, bytes_to_hex, hex_to_bytes, xor_bytes
import uhashlib  # Import uhashlib


# --- Configuration ---
CS = machine.Pin(5, machine.Pin.OUT) # CS pin (GP5)
spi = machine.SPI(0, baudrate=1000000, polarity=0, phase=0)
nfc = PN532_SPI(spi, CS)

# --- SIMON64/128 Key ---
KEY = hex_to_bytes("000102030405060708090A0B0C0D0E0F")  # 128-bit key
cipher = SimonCipher(KEY)


# --- HMAC-SHA256 ---
def calculate_hmac(key, data):
    """Calculates HMAC-SHA256.

    Args:
        key: The HMAC key (bytes).
        data: The data to authenticate (bytes).

    Returns:
        The HMAC-SHA256 digest (bytes).
    """
    key_len = len(key)
    if key_len > 64:
        key = uhashlib.sha256(key).digest()
        key_len = len(key)

    if key_len < 64:
        key = key + b'\x00' * (64-key_len)  # Pad

    o_key_pad = xor_bytes(key, b'\x5c' * 64)
    i_key_pad = xor_bytes(key, b'\x36' * 64)

    inner_hash = uhashlib.sha256(i_key_pad + data).digest()
    outer_hash = uhashlib.sha256(o_key_pad + inner_hash).digest()
    return outer_hash


def main():
    print("Initializing PN532...")
    nfc.begin()

    versiondata = nfc.getFirmwareVersion()
    if not versiondata:
        print("Didn't find PN53x board")
        raise RuntimeError("Didn't find PN53x board")

    print("Found chip PN5{:02X} Firmware ver. {:d}.{:d}".format(
        (versiondata >> 24) & 0xFF, (versiondata >> 16) & 0xFF, (versiondata >> 8) & 0xFF
    ))

    nfc.setPassiveActivationRetries(0xFF)
    nfc.SAMConfig()

    print("Waiting for an ISO14443A card...")
    while True:
        try:
            uid = nfc.readPassiveTargetID(
                cardbaudrate=nfc.MIFARE_106KBPS, timeout=1000
            )
            if uid is not None:  
                print("Found card with UID:", bytes_to_hex(uid))

                # --- Application (Send APDU) ---
                select_apdu = hex_to_bytes("00A4040007F001020304050600")
                response = nfc.inDataExchange(select_apdu)
                print("Select APDU Response:", bytes_to_hex(response[0]))

                # --- Get Data Command (Custom APDU) ---
                get_data_apdu = hex_to_bytes("9000000000")
                response = nfc.inDataExchange(get_data_apdu)

                if response[0] is None:  # Check if response[0] is None
                    print("No data from card")
                    continue
                response_data = response[0]  

                print("Get Data Response:", bytes_to_hex(response_data))


                # --- Parse Response (IV || Ciphertext || HMAC) ---
                iv_size = 8  # SIMON64/128 block size
                hmac_size = 32  # SHA256 hash size
                if len(response_data) < iv_size + hmac_size:
                    print("Invalid response length")
                    continue

                iv = response_data[:iv_size]
                ciphertext = response_data[iv_size:-hmac_size]
                received_hmac = response_data[-hmac_size:]


                # --- Verify HMAC ---
                calculated_hmac = calculate_hmac(KEY, iv + ciphertext)  
                if calculated_hmac != received_hmac:
                    print("HMAC verification failed!")
                    continue

                # --- Decrypt Data ---
                decrypted_block = cipher.decrypt_block(ciphertext)
                print("Decrypted Data:", bytes_to_hex(decrypted_block))
                try:
                    decoded_string = decrypted_block.decode('utf-8')
                    print("Decrypted String:", decoded_string)
                except UnicodeDecodeError:
                    print("Decrypted String: (Could not decode as UTF-8)")

                time.sleep(1)  

        except RuntimeError as e:
            print("Error:", e)
            time.sleep(1)
        except OSError as e: #Catching OSError
            print("OSError:",e)
            time.sleep(1)
        except Exception as e: #Catching all other exceptions
            print("An unexpected error occured:",e)
            time.sleep(1)



if __name__ == "__main__":
    main()
```

#### Tag(Pico-2):

```python
import machine
import time
from pn532 import PN532_SPI
from simon import SimonCipher, bytes_to_hex, hex_to_bytes, xor_bytes
import urandom
import uhashlib 


#pin
CS = machine.Pin(5, machine.Pin.OUT)
spi = machine.SPI(0, baudrate=1000000, polarity=0, phase=0)
nfc = PN532_SPI(spi, CS)


KEY = hex_to_bytes("000102030405060708090A0B0C0D0E0F")  # 128-bit key
cipher = SimonCipher(KEY)

#Data 
DATA = "Secret Data!".encode('utf-8')

# --- HMAC-SHA256 ---
def calculate_hmac(key, data):
    """Calculates HMAC-SHA256.

    Args:
        key: The HMAC key (bytes).
        data: The data to authenticate (bytes).

    Returns:
        The HMAC-SHA256 digest (bytes).
    """
    key_len = len(key)
    if key_len > 64:
        key = uhashlib.sha256(key).digest()
        key_len = len(key)

    if key_len < 64:
        key = key + b'\x00' * (64 - key_len)  # Pad

    o_key_pad = xor_bytes(key, b'\x5c' * 64)
    i_key_pad = xor_bytes(key, b'\x36' * 64)

    inner_hash = uhashlib.sha256(i_key_pad + data).digest()
    outer_hash = uhashlib.sha256(o_key_pad + inner_hash).digest()
    return outer_hash



def prepare_response(data_to_send):
    """Prepares the encrypted response data, including IV and HMAC."""
    iv = urandom.bytes(8)  # Generate a random 8-byte IV
    padded_data = data_to_send
    # PKCS#7 Padding
    pad_len = 8 - (len(padded_data) % 8)
    padded_data += bytes([pad_len] * pad_len)
    encrypted_data = cipher.encrypt_block(padded_data)
    hmac = calculate_hmac(KEY, iv + encrypted_data)
    return iv + encrypted_data + hmac



def main():
    print("Initializing PN532 in card emulation mode...")
    nfc.begin()

    versiondata = nfc.getFirmwareVersion()
    if not versiondata:
        print("Didn't find PN53x board")
        raise RuntimeError("Didn't find PN53x board")

    print("Found chip PN5{:02X} Firmware ver. {:d}.{:d}".format(
        (versiondata >> 24) & 0xFF, (versiondata >> 16) & 0xFF, (versiondata >> 8) & 0xFF
    ))

    nfc.setPassiveActivationRetries(0xFF)
    nfc.SAMConfig()
    print("Waiting for an ISO14443A card (to read)...")

    # --- Main Emulation Loop ---
    while True:
        try:
            
            success, uid = nfc.targetInit(timeout=500) 
            if not success:
                continue  

            print("Reader detected! UID:", bytes_to_hex(uid))


            while True:  
                try:

                    #APDU command from the reader
                    ret, received_data = nfc.targetGetData() 
                    if not ret: 
                        break 

                    print("Received APDU:", bytes_to_hex(received_data))

                    # --- Process Command ---
                    if received_data == hex_to_bytes("00A4040007F001020304050600"):  
                        # success response (90 00)
                        nfc.targetSetData(hex_to_bytes("9000")) 

                    elif received_data == hex_to_bytes("9000000000"):  #Get Data
                        response_data = prepare_response(DATA)
                        nfc.targetSetData(response_data) 

                    else:
                        #error response
                        nfc.targetSetData(hex_to_bytes("6F00"))


                except RuntimeError as e:
                    print("RuntimeError in inner loop:", e)
                    break  
                except OSError as e:
                    print("OSError in inner loop",e)
                    break
        except RuntimeError as e:
             print("RuntimeError in outer loop", e) 
        except OSError as e:
            print("OSError in outer loop:",e)
        except Exception as e:
            print("An unexpected error in outer loop",e)

if __name__ == "__main__":
    main()
```

### Communication
- ***Initial Sequence***
- **Reader:** the Reader Pico successfully detects the emulated tag (PN532 on Pico 2). This returns the UID of the emulated tag
- **Tag:** The PN532 on the Tag Pico, in card emulation mode, responds to the reader's presence according to the ISO14443A protocol. This happens at the low-level RF communication layer, handled by the PN532 itself
- **Data Exchanged (Low-Level):** At this stage, there's basic anti-collision and selection information exchanged (like the UID), but no application-level data

- ***Data Transmission***
- **Reader:** The Reader sends this APDU using `nfc.inDataExchange(select_apdu)`
- **Tag:** The `nfc.targetGetData()` call within the inner loop on the Tag Pico _receives_ this APDU. Then the tag's code checks if `received_data` matches the "SELECT APPLICATION" APDU. If success, Then the Tag sends this response using `nfc.targetSetData(hex_to_bytes("9000"))`
*If success:*
- **Reader:** The Reader constructs the "GET DATA" APDU and sends this APDU using `nfc.inDataExchange(get_data_apdu)`
- **Tag:** The tag's code checks if `received_data` matches the "GET DATA" APDU.
- **Tag:** Generates a special response as a message then the tag sends this combined response using `nfc.targetSetData(...)`
- **Reader:** The Reader extracts the IV, ciphertext, and HMAC based on their known lengths.
- **Reader:** After processing, reader waits for a while, then returns to reading for NFCs.