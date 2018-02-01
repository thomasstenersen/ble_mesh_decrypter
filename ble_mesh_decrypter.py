# Copyright (c) 2016, Nordic Semiconductor
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of ble_mesh_decrypter nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from utils import key
import json
import struct
import sys


class MeshDecrypter(object):
    def __init__(self, appkeys, devkeys, netkeys):
        self.appkeys = appkeys
        self.devkeys = devkeys
        self.netkeys = netkeys

    def decrypt(self, pdu):
        MESH_MESSAGE_MIN_LENGTH = 17
        if (not isinstance(pdu, bytes) or
            len(pdu) < MESH_MESSAGE_MIN_LENGTH):
            return pdu

        ivi = pdu[0] & 0x01
        nid = pdu[0] & 0x7f

        cleartext = None
        netkey = None
        for key in self.netkeys:
            # Only run deobfuscation and decrypt if the NID matches
            if key.nid == nid:
                pdu_deobfuscated = key.deobfuscate(pdu)
                cleartext = key.decrypt(pdu_deobfuscated)
                if cleartext is not None:
                    netkey = key
                    pdu = cleartext
                    break
        if not (cleartext and netkey):
            print("Network layer decryption failed")

        ctl = (pdu[1] & 0x80) > 0
        seg = (pdu[9] & 0x80) > 0
        akf = (pdu[9] & 0x40) > 0
        aid = (pdu[9] & 0x3f)
        cleartext = None
        if ctl:
            # It's a transport control message, i.e.,
            # unencrypted by the transport layer.
            return pdu

        if akf:
            for key in self.appkeys:
                if key.aid == aid:
                    cleartext = key.decrypt(netkey, pdu)
                    if cleartext is not None:
                        pdu = cleartext
                        break
        else:
            for key in self.devkeys:
                cleartext = key.decrypt(neykey, pdu)
                if cleartext is not None:
                    pdu = cleartext
                    break
        return pdu


def test():
    # From the Mesh Profile v1.0 sample data #19
    appkey = "63964771734fbd76e3b40519d1d94a48"
    netkey = "7dd7364cd842ad18c17c2b820c84c3d6"
    iv_index = 0x12345678
    md = MeshDecrypter(
        [key.ApplicationKey(bytes.fromhex(appkey))],
        [],
        [key.NetworkKey(bytes.fromhex(netkey), iv_index)])
    sample_data = "68110edeecd83c3010a05e1b23a926023da75d25ba91793736"
    access_pdu = md.decrypt(bytes.fromhex(sample_data))[10:-8].hex()
    if access_pdu == "04000000010703":
        print("Decrypted sample data #19 successfully")
    else:
        print("Error decrypting sample data")


def decrypt(pdu):
    with open("keys.json", "r") as f:
        keys = json.load(f)

    appkeys = [key.ApplicationKey(bytes.fromhex(k["key"])) for k in keys["appkeys"]]
    devkeys = [key.DeviceKey(bytes.fromhex(k["key"]), struct.unpack(">H", bytes.fromhex(k["address"]))[0]) for k in keys["devkeys"]]
    netkeys = [key.NetworkKey(bytes.fromhex(k["key"]), struct.unpack(">I", bytes.fromhex(k["ivindex"]))[0]) for k in keys["netkeys"]]

    pdu = bytes.fromhex(pdu)
    md = MeshDecrypter(appkeys, devkeys, netkeys)
    return md.decrypt(pdu).hex()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        test()
    else:
        print(decrypt(sys.argv[1]))
