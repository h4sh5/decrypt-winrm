#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK

# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

# Fork / modifications by Haoxi Tan (haoxi.tan@gmail.com)
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""
Script that can read a Wireshark capture .pcapng for a WinRM exchange and decrypt the messages. Currently only supports
exchanges that were authenticated with NTLM. This is really a POC, a lot of things are missing like NTLMv1 support,
shorter signing keys, better error handling, etc.
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import argparse
import base64
import hashlib
import hmac
import os
import pyshark
import binascii
import sys
import struct
import xml.dom.minidom

from cryptography.hazmat.primitives.ciphers import (
    algorithms,
    Cipher,
)

from cryptography.hazmat.backends import (
    default_backend,
)

try:
    import argcomplete
except ImportError:
    argcomplete = None


class SecurityContext:

    def __init__(self, port, nt_hash):
        self.port = port
        self.tokens = []
        self.nt_hash = nt_hash
        self.complete = False

        self.key_exch = False
        self.session_key = None
        self.sign_key_initiate = None
        self.sign_key_accept = None
        self.seal_handle_initiate = None
        self.seal_handle_accept = None

        self.__initiate_seq_no = 0
        self.__accept_seq_no = 0

    @property
    def _initiate_seq_no(self):
        val = self.__initiate_seq_no
        self.__initiate_seq_no += 1
        return val

    @property
    def _accept_seq_no(self):
        val = self.__accept_seq_no
        self.__accept_seq_no += 1
        return val

    def add_token(self, token):
        self.tokens.append(token)

        if token.startswith(b"NTLMSSP\x00\x03"):
            # Extract the info required to build the session key
            nt_challenge = self._get_auth_field(20, token)
            b_domain = self._get_auth_field(28, token) or b""
            b_username = self._get_auth_field(36, token) or b""
            encrypted_random_session_key = self._get_auth_field(52, token)
            flags = struct.unpack("<I", token[60:64])[0]

            encoding = 'utf-16-le' if flags & 0x00000001 else 'windows-1252'
            domain = b_domain.decode(encoding)
            username = b_username.decode(encoding)

            # Derive the session key
            nt_proof_str = nt_challenge[:16]
            response_key_nt = hmac_md5(self.nt_hash, (username.upper() + domain).encode('utf-16-le'))
            key_exchange_key = hmac_md5(response_key_nt, nt_proof_str)
            self.key_exch = bool(flags & 0x40000000)

            if self.key_exch and (flags & (0x00000020 | 0x00000010)):
                self.session_key = rc4k(key_exchange_key, encrypted_random_session_key)

            else:
                self.session_key = key_exchange_key

            # Derive the signing and sealing keys
            self.sign_key_initiate = signkey(self.session_key, 'initiate')
            self.sign_key_accept = signkey(self.session_key, 'accept')
            self.seal_handle_initiate = rc4init(sealkey(self.session_key, 'initiate'))
            self.seal_handle_accept = rc4init(sealkey(self.session_key, 'accept'))
            self.complete = True

    def unwrap_initiate(self, data):
        print('unwrap_initiate',file=sys.stderr)
        return self._unwrap(self.seal_handle_initiate, self.sign_key_initiate, self._initiate_seq_no, data)

    def unwrap_accept(self, data):
        print('unwrap_accept',file=sys.stderr)
        return self._unwrap(self.seal_handle_accept, self.sign_key_accept, self._accept_seq_no, data)

    def _unwrap(self, handle, sign_key, seq_no, data):
        header = data[4:20]
        enc_data = data[20:]
        dec_data = handle.update(enc_data)

        b_seq_num = struct.pack("<I", seq_no)

        checksum = hmac_md5(sign_key, b_seq_num + dec_data)[:8]
        if self.key_exch:
            checksum = handle.update(checksum)
        actual_header = b"\x01\x00\x00\x00" + checksum + b_seq_num

        if header != actual_header:
            # raise Exception("Signature verification failed")
            print("Signature verification failed")
            # meh, continue

        return dec_data

    def _get_auth_field(self, offset, token):
        field_len = struct.unpack("<H", token[offset:offset + 2])[0]
        if field_len:
            field_offset = struct.unpack("<I", token[offset + 4:offset + 8])[0]
            return token[field_offset:field_offset + field_len]


def hmac_md5(key, data):
    return hmac.new(key, data, digestmod=hashlib.md5).digest()


def md4(m):
    return hashlib.new('md4', m).digest()


def md5(m):
    return hashlib.md5(m).digest()


def ntowfv1(password):
    return md4(password.encode('utf-16-le'))


def rc4init(k):
    arc4 = algorithms.ARC4(k)
    return Cipher(arc4, mode=None, backend=default_backend()).encryptor()


def rc4k(k, d):
    return rc4init(k).update(d)


def sealkey(session_key, usage):
    direction = b"client-to-server" if usage == 'initiate' else b"server-to-client"
    return md5(session_key + b"session key to %s sealing key magic constant\x00" % direction)


def signkey(session_key, usage):
    direction = b"client-to-server" if usage == 'initiate' else b"server-to-client"
    return md5(session_key + b"session key to %s signing key magic constant\x00" % direction)


def unpack_message(data):
    # parts = data.split(b'--Encrypted Boundary\r\n')
    parts = list(filter(None, parts))

    messages = []
    for i in range(0, len(parts), 2):
        header = parts[i].strip()
        payload = parts[i + 1]

        length = int(header.split(b"Length=")[1])

        # remove the end MIME block if it exists
        if payload.endswith(b"--Encrypted Boundary--\r\n"):
            payload = payload[:len(payload) - 24]

        wrapped_data = payload.replace(b"Content-Type: application/octet-stream\r\n", b"")

        messages.append((length, wrapped_data))

    return messages


def pretty_xml(xml_str):
    dom = xml.dom.minidom.parseString(xml_str)
    return dom.toprettyxml()


def main():
    """Main program entry point."""
    args = parse_args()

    if args.password:
        nt_hash = ntowfv1(args.password)

    else:
        nt_hash = base64.b16decode(args.hash.upper())

    captures = pyshark.FileCapture(os.path.expanduser(os.path.expandvars(args.path)),
                                   display_filter='http and tcp.port == %d' % args.port)

    contexts = []
    for cap in captures:
        try:
            source_port = int(cap.tcp.srcport)
            unique_port = source_port if source_port != args.port else int(cap.tcp.dstport)

            auth_token = None
            if hasattr(cap.http, 'authorization'):
                b64_token = cap.http.authorization.split(' ')[1]
                auth_token = base64.b64decode(b64_token)

            elif hasattr(cap.http, 'www_authenticate'):
                parts = cap.http.www_authenticate.split(' ')
                if len(parts) > 1:
                    b64_token = parts[1]
                    try:
                        auth_token = base64.b64decode(b64_token)
                    except Exception:
                        continue
                else:
                    continue

            context = None
            if auth_token:
                if not auth_token.startswith(b"NTLMSSP\x00"):
                    continue

                if auth_token.startswith(b"NTLMSSP\x00\x01"):
                    context = SecurityContext(unique_port, nt_hash)
                    contexts.append(context)

                else:
                    context = [c for c in contexts if c.port == unique_port][-1]
                    if not context:
                        raise ValueError("Missing exisitng NTLM security context")

                context.add_token(auth_token)

            if hasattr(cap.http, 'file_data'):
                if not context:
                    context = next(c for c in contexts if c.port == unique_port)

                if not context.complete:
                    raise ValueError("Cannot decode message without completed context")

                # file_data = cap.http.file_data #.binary_value
                # messages = unpack_message(file_data)
                length = int(cap.mime_multipart.data_len)
                msgdata = binascii.unhexlify(cap.mime_multipart.data)
                messages = [(length, msgdata)]

                unwrap_func = context.unwrap_accept if source_port == args.port else context.unwrap_initiate

                dec_msgs = []
                for length, enc_data in messages:
                    msg = unwrap_func(enc_data)
                    # if len(msg) != length:
                        # raise ValueError("Message decryption failed")
                    # print(f'decrypted msg ({len(msg)}):',msg)
                    try:
                        dec_msgs.append(pretty_xml(msg.decode('utf-8')))
                    except Exception as e:
                        print("Exception: ", e)
                        dec_msgs.append("[bad message]")


                dec_msgs = "\n".join(dec_msgs)
                print("No: %s | Time: %s | Source: %s | Destination: %s\n%s\n"
                      % (cap.number, cap.sniff_time.isoformat(), cap.ip.src_host, cap.ip.dst_host, dec_msgs))

        except Exception as e:
            raise Exception("Failed to process frame: %s" % cap.number) from e


def parse_args():
    """Parse and return args."""
    parser = argparse.ArgumentParser(description='Parse network captures from WireShark and decrypts the WinRM '
                                                 'messages that were exchanged.')

    parser.add_argument('path',
                        type=str,
                        help='The path to the .pcapng file to decrypt.')

    parser.add_argument('--port',
                        dest='port',
                        default=5985,
                        type=int,
                        help='The port to scan for the WinRM HTTP packets (default: 5985).')

    secret = parser.add_mutually_exclusive_group()

    secret.add_argument('-p', '--password',
                        dest='password',
                        help='The password for the account that was used in the authentication.')

    secret.add_argument('-n', '--hash',
                        dest='hash',
                        help='The NT hash for the account that was used in the authentication.')

    if argcomplete:
        argcomplete.autocomplete(parser)

    return parser.parse_args()


if __name__ == '__main__':
    main()
