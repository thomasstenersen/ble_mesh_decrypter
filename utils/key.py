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

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import struct
from utils import kdf


class NetworkKey(object):
    def __init__(self, key, iv_index):
        self.key = key
        out = kdf.k2(key, b'\x00')
        self.nid = out[0]
        self.encryption_key = out[1:17]
        self.privacy_key = out[17:]
        self.iv_index_set(iv_index)

    def iv_index_set(self, iv_index):
        self.iv_index = iv_index

    def deobfuscate(self, pdu):
        """Attempts to deobfuscate the network PDU header (CTL, TTL, SEQ, SRC)"""
        iv_index = self.iv_index_get(pdu)
        privacy_random = pdu[7:(7+7)]
        pecb_input = (bytes(5)
                      + struct.pack(">I", iv_index)
                      + privacy_random)
        pecb = AES.new(self.privacy_key, mode=AES.MODE_ECB).encrypt(pecb_input)
        return bytes([pdu[0]]) + strxor(pdu[1:7], pecb[0:6]) + pdu[7:]

    def iv_index_get(self, pdu):
        """Gets the IV index used for decryption based on the IVI bit"""
        # Check the IVI bit to see if we're using the current or previous IV index.
        if (self.iv_index & 0x01) != (pdu[0] >> 8):
            iv_index = self.iv_index - 1
        else :
            iv_index = self.iv_index
        return iv_index

    def decrypt(self, pdu):
        iv_index = self.iv_index_get(pdu)
        # Ref. Mesh Profile spec v1.0 table 3.45
        # Exploit the PDU layout according to table 3.7
        nonce = (bytes(1)
                 + pdu[1:(1 + 1 + 3 + 2)]
                 + bytes(2)
                 + struct.pack(">I", iv_index))
        if (pdu[1] & 0x80) > 0:
            mac_len = 8
        else:
            mac_len = 4

        MIN_NETWORK_LEN = 10
        if (len(pdu) - MIN_NETWORK_LEN - mac_len) < 0:
            # print("Length of the PDU is too small: ", len(pdu))
            return None

        ciphertext = pdu[7:-mac_len]
        mac = pdu[-mac_len:]
        self.ccm = AES.new(self.encryption_key, mode=AES.MODE_CCM,
                           nonce=nonce,
                           mac_len=mac_len,
                           msg_len=len(ciphertext),
                           assoc_len=0)
        try:
            cleartext = self.ccm.decrypt_and_verify(ciphertext, mac)
            return pdu[0:7] + cleartext + mac
        except ValueError as e:
            # MAC check failed
            # print("MAC check failed: ", mac.hex())
            return None


class ApplicationKey(object):
    def __init__(self, key):
        self.key = key
        self.aid = kdf.k4(self.key)[0]

    def decrypt(self, netkey, pdu):
        ctl = (pdu[1] & 0x80) > 0
        seg = (pdu[9] & 0x80) > 0
        akf = (pdu[9] & 0x40) > 0
        aid = (pdu[9] & 0x3f)
        if ctl:
            # It's a transport control message, i.e., unencrypted by the transport layer.
            return pdu

        if self.aid != aid or not akf:
            # print("Not encrypted with an application key or not _this_ application key", aid, self.aid, akf)
            return pdu

        if not seg:
            # MAC/MIC length is always 4 bytes for unsegmented access messages
            # Also need to add the 4 bytes in the network PDU
            mac_len = 4
            ciphertext = pdu[10:-(mac_len + 4)]
            mac = pdu[-(mac_len + 4):-4]
            # As with the network decryption, we exploit the PDU structure
            nonce = (b'\x01'
                     + b'\x00'
                     + pdu[2:(2 + 3 + 2 + 2)]
                     + struct.pack(">I", netkey.iv_index_get(pdu)))
            ccm = AES.new(self.key, mode=AES.MODE_CCM,
                          nonce=nonce,
                          mac_len=mac_len,
                          msg_len=len(ciphertext),
                          assoc_len=0)
            try:
                cleartext = ccm.decrypt_and_verify(ciphertext, mac)
                return pdu[0:10] + cleartext + pdu[10 + len(cleartext):]
            except ValueError as e:
                # print("ApplicationKey decrypt failed ")
                return pdu
        else:
            return pdu


class DeviceKey(object):
    def __init__(self, key, address):
        self.key = key
        self.address = address

    def decrypt(self, pdu):
        ctl = (pdu[1] & 0x80) > 0
        seg = (pdu[9] & 0x80) > 0
        akf = (pdu[9] & 0x40) > 0
        aid = (pdu[9] & 0x3f)
        if ctl:
            # It's a transport control message, i.e., unencrypted by the transport layer.
            return pdu

        if aid != 0 or akf:
            # Encrypted with an application key
            return pdu

        if not seg:
            # MAC/MIC length is always 4 bytes for unsegmented access messages
            mac_len = 4
            ciphertext = pdu[10:-(mac_len + 4)]
            mac = pdu[-(mac_len + 4):]
            # As with the network decryption, we exploit the PDU structure
            nonce = (b'\x02'
                     + b'\x00'
                     + pdu[2:(2 + 3 + 2 + 2)]
                     + struct.pack(">I", netkey.iv_index_get(pdu)))
            ccm = AES.new(self.key, mode=AES.MODE_CCM,
                          nonce=nonce,
                          mac_len=mac_len,
                          msg_len=len(ciphertext),
                          assoc_len=0)
            try:
                cleartext = ccm.decrypt_and_verify(ciphertext, mac)
                return pdu[0:10] + cleartext + pdu[10 + len(cleartext):]
            except ValueError as e:
                # print("ApplicationKey decrypt failed ")
                return pdu
        else:
            return pdu
