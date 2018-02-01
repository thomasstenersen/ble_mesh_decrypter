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
from Crypto.Hash import CMAC


def s1(m):
    if isinstance(m, str):
        m = bytes.fromhex(str)
    elif isinstance(m, bytearray):
        m = bytes(m)

    cipher = CMAC.new(bytes(16), ciphermod=AES).update(m)
    return cipher.digest()


def k1(n, salt, p):
    t = CMAC.new(salt, ciphermod=AES).update(n).digest()
    return CMAC.new(t, ciphermod=AES).update(p).digest()


def k2(n, p):
    salt = s1(b'smk2')
    t = CMAC.new(salt, ciphermod=AES).update(n).digest()
    t0 = b''
    t1 = CMAC.new(t, ciphermod=AES).update(t0 + p + b'\x01').digest()
    t2 = CMAC.new(t, ciphermod=AES).update(t1 + p + b'\x02').digest()
    t3 = CMAC.new(t, ciphermod=AES).update(t2 + p + b'\x03').digest()
    result = bytearray((t1 + t2 + t3)[-33:])
    result[0] = result[0] & 0x7F
    return bytes(result)


def k3(n):
    salt = s1(b'smk3')
    t = CMAC.new(salt, ciphermod=AES).update(n).digest()
    return CMAC.new(t, ciphermod=AES).update(b'id64' + b'\x01').digest()[-8:]


def k4(n):
    salt = s1(b'smk4')
    t = CMAC.new(salt, ciphermod=AES).update(n).digest()
    result = CMAC.new(t, ciphermod=AES).update(b'id6' + b'\x01').digest()
    result = bytearray([result[-1]])[0] & 0x3f
    return bytes([result])


def print_results(name, expected, actual):
    if actual != expected:
        print(name + " failed.")
        print("actual  : ", actual)
        print("expected: ", expected)
    else:
        print(name + " success.")


def test_k1():
    k1_n = bytes.fromhex("3216d1509884b533248541792b877f98")
    k1_salt = bytes.fromhex("2ba14ffa0df84a2831938d57d276cab4")
    k1_p = bytes.fromhex("5a09d60797eeb4478aada59db3352a0d")
    # k1_t = bytes.fromhex("c764bea25cf9738b08956ea3c712d5af")
    k1_expected = bytes.fromhex("f6ed15a8934afbe7d83e8dcb57fcf5d7")

    out = k1(k1_n, k1_salt, k1_p)
    print_results("k1", k1_expected, out)


def test_k2():
    k2_n = bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
    k2_p = bytes.fromhex("00")
    nid_expected = bytes.fromhex("7f")
    encryption_key_expected = bytes.fromhex("9f589181a0f50de73c8070c7a6d27f46")
    privacy_key_expected = bytes.fromhex("4c715bd4a64b938f99b453351653124f")
    out = k2(k2_n, k2_p)
    expected = nid_expected + encryption_key_expected + privacy_key_expected
    print_results("k2", expected, out)


def test_k3():
    k3_n = bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
    expected = bytes.fromhex("ff046958233db014")
    out = k3(k3_n)
    print_results("k3", expected, out)


def test_k4():
    k4_n = bytes.fromhex("3216d1509884b533248541792b877f98")
    expected = bytes.fromhex("38")
    out = k4(k4_n)
    print_results("k4", expected, out)


def test():
    test_k1()
    test_k2()
    test_k3()
    test_k4()


if __name__ == "__main__":
    test()
