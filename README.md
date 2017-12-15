# Bluetooth Mesh packet decryption library

This library enables easy decryption of [Bluetooth Mesh](https://www.bluetooth.com/specifications/mesh-specifications)
packets. It's written to be used with Python 3.

## Usage

Basic usage:
```
python ble_mesh_decrypter.py <payload>
```


Example using the Bluetooth Mesh v1.0 sample data #19:

```
$ python ble_mesh_decrypter.py 68110edeecd83c3010a05e1b23a926023da75d25ba91793736
68030000091201ffff660400000001070365f43fc591793736
```

## Disclaimer
This is experimental software that might more often than not fail to decrypt the payload. If any
error occurs, it should simply return the existing payload.
