#!/usr/bin/env python

from __future__ import print_function

import binascii
import os
import random
import select
import socket
import struct
import subprocess as sp
import sys
import time
from ctypes import (
    CDLL,
    BigEndianStructure,
    addressof,
    c_uint8,
    c_uint16,
    c_uint32,
    create_string_buffer,
)
from ctypes.util import find_library

__version__ = "2023.06.05.0"

# linux/sched.h
CLONE_NEWNET = 0x40000000

# linux/if_ether.h
ETH_ALEN = 6
ETH_HLEN = 14
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD

# /etc/protocols
PROTO_TCP = 6


def errcheck(rc, func, args):
    if rc:
        raise RuntimeError("Unable to enter namespace (are you root?)")


LIBC = CDLL(find_library("c"), use_errno=True)
LIBC.setns.errcheck = errcheck

NEXTHOP_META = """\
neigh=($(ip -__VERSION__ neigh show __NHIP__))
intf=${neigh[2]}
dmac=${neigh[4]}
link=($(ip -__VERSION__ link show "${intf}" | tail -n1))
smac="${link[1]}"
route=($(ip -__VERSION__ route get __NHIP__/__MASK__))
sip="${route[__VERSION__]}"
echo -n "${intf} ${dmac} ${smac} ${sip}"
"""

VERSION = None  # declared in scan()


class Header(BigEndianStructure):
    def __len__(self):
        return len(self.bytez)

    def __str__(self):
        return str(bytearray(self))

    @property
    def bytez(self):
        return bytes(bytearray(self))

    @property
    def hex(self):
        return binascii.hexlify(self.bytez)

    @staticmethod
    def chksum(header):
        """Calculate the checksum of a given `header`.

        Args:
            header (bytes): Byte-representation of a header.

        Returns:
            int: The calculated checksum.

        """
        # https://tools.ietf.org/html/rfc1071#section-3
        dw, data = 0, bytearray(header)
        for i, byte in enumerate(data):
            dw += byte if i & 1 else byte << 8
        while dw >> 16:
            dw = (dw >> 16) + (dw & 0xFFFF)
        return 0xFFFF - dw


class Ethernet(Header):
    """An Ethernet header."""

    # https://tools.ietf.org/html/rfc1042
    # fmt: off
    _fields_ = [
        ("dmac",        c_uint8 * 6),   # destination address
        ("smac",        c_uint8 * 6),   # source address
        ("ethertype",   c_uint16, 16),  # ethertype
    ]
    # fmt: on

    @classmethod
    def from_args(cls, dmac, smac, ethertype):
        return cls.from_buffer_copy(struct.pack("!6s6sH", cls.mac_to_bytes(dmac), cls.mac_to_bytes(smac), ethertype,))

    @staticmethod
    def mac_to_bytes(mac):
        hex_digits = set("0123456789ABCDEFabcdef")
        clean = "".join(c for c in mac if c in hex_digits)
        return binascii.a2b_hex(clean)


class IPv4(Header):
    """An Internet Protocol version 4 header."""

    # https://tools.ietf.org/html/rfc791#section-3.1
    # fmt: off
    _fields_ = [
        ("version",     c_uint8,  4),   # version
        ("ihl",         c_uint8,  4),   # internet header length
        ("dscp",        c_uint8,  6),   # differentiated services code point
        ("ecn",         c_uint8,  2),   # explicit congestion notification
        ("length",      c_uint16, 16),  # total length
        ("ident",       c_uint16, 16),  # identification
        ("flags",       c_uint16, 3),   # flags
        ("frag",        c_uint16, 13),  # fragment offset
        ("ttl",         c_uint8,  8),   # time to live
        ("proto",       c_uint8,  8),   # protocol
        ("chksum",      c_uint16, 16),  # header checksum
        ("sip_",        c_uint8 * 4),   # source address
        ("dip_",        c_uint8 * 4),   # destination address
    ]
    # fmt: on

    @property
    def sip(self):
        return str(bytearray(self.sip_))

    @property
    def dip(self):
        return str(bytearray(self.dip_))

    @classmethod
    def from_args(
        cls,
        _version=0x4,
        _ihl=0x5,
        _dscp=0x0,
        _ecn=0x0,
        _length=0x28,
        _ident=None,
        _flags=0x0,
        _frag=0x0,
        _ttl=0x40,
        _proto=PROTO_TCP,
        _chksum=0x0,
        sip="127.0.0.1",
        dip="127.0.0.1",
    ):
        return cls.from_buffer_copy(
            struct.pack(
                "!BBHHHBBH4s4s",
                ((_version << 4) | _ihl) & 0xFF,
                ((_dscp << 2) | _ecn) & 0xFF,
                _length,
                _ident or random.getrandbits(16),
                ((_flags << 13) | _frag) & 0xFFFF,
                _ttl,
                _proto,
                _chksum,
                socket.inet_aton(sip),
                socket.inet_aton(dip),
            )
        )

    def calc_chksum(self):
        self.chksum = Header.chksum(self.bytez)


class IPv6(Header):
    """An Internet Protocol version 6 header."""

    # https://tools.ietf.org/html/rfc2460#section-3
    # fmt: off
    _fields_ = [
        ("version", c_uint32,  4),   # version
        ("tclass",  c_uint32,  8),   # traffic class
        ("flow",    c_uint32,  20),  # flow label
        ("plen",    c_uint32,  16),  # payload length
        ("nxt",     c_uint32,  8),   # next header
        ("hlim",    c_uint32,  8),   # hop limit
        ("sip_",    c_uint32 * 4),   # source address
        ("dip_",    c_uint32 * 4),   # destination address
    ]
    # fmt: on

    @classmethod
    def from_args(
        cls, _version=0x6, _tclass=0x0, _flow=0x0, _plen=0x14, _nxt=PROTO_TCP, _hlim=0x0, sip="::1", dip="::1",
    ):
        shi, slo = struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, sip))
        dhi, dlo = struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, dip))
        return cls.from_buffer_copy(
            struct.pack(
                "!LLQQQQ",
                ((_version << 28) | (_tclass << 20) | _flow) & 0xFFFFFFFF,
                ((_plen << 16) | (_nxt << 8) | _hlim) & 0xFFFFFFFF,
                shi & 0xFFFFFFFFFFFFFFFF,
                slo & 0xFFFFFFFFFFFFFFFF,
                dhi & 0xFFFFFFFFFFFFFFFF,
                dlo & 0xFFFFFFFFFFFFFFFF,
            )
        )

    @property
    def sip(self):
        return bytes(bytearray(self.sip_))

    @property
    def dip(self):
        return bytes(bytearray(self.dip_))


class TCP(Header):
    """A Transmission Control Protocol header."""

    # https://tools.ietf.org/html/rfc793#section-3.1
    # fmt: off
    _fields_ = [
        ("sport",       c_uint16, 16),  # source port
        ("dport",       c_uint16, 16),  # destination port
        ("seq",         c_uint32, 32),  # sequence number
        ("ack",         c_uint32, 32),  # acknowledgement number
        ("dataofs",     c_uint8,  4),   # data offset
        ("reserved",    c_uint8,  3),   # reserved
        ("flags",       c_uint16, 9),   # control bits
        ("window",      c_uint16, 16),  # window
        ("chksum",      c_uint16, 16),  # checksum
        ("urgptr",      c_uint16, 16),  # urgent pointer
    ]
    # fmt: on

    # fmt: off
    FLAGS = {
        "NS":  1 << 8,  # nonce sum
        "CWR": 1 << 7,  # congestion window reduced
        "ECN": 1 << 6,  # explicit congestion notification
        "URG": 1 << 5,  # urgent pointer field significant
        "ACK": 1 << 4,  # acknowledgement field significant
        "PSH": 1 << 3,  # push function
        "RST": 1 << 2,  # reset the connection
        "SYN": 1 << 1,  # synchronize sequence numbers
        "FIN": 1 << 0,  # no more data from sender
    }
    # fmt: on

    @classmethod
    def from_args(
        cls,
        sport=None,
        dport=None,
        seq=None,
        ack=0x0,
        _dataofs=0x5,
        _reserved=None,  # dummy, ignored
        flags=FLAGS["SYN"],
        _window=8192,
        _chksum=0x0,
        _urgptr=0x0,
    ):
        _reserved = 0x0

        # fmt: off
        return cls.from_buffer_copy(
            struct.pack(
                "!HHLLHHHH",
                sport,
                dport,
                seq or random.getrandbits(0x20),
                ack,
                ((_dataofs << 12) | (_reserved << 9) | flags) & 0xFFFF,
                _window,
                _chksum,
                _urgptr,
            )
        )
        # fmt: on

    def calc_chksum(self, ip):
        self.chksum = 0x0
        if VERSION == 4:
            # https://tools.ietf.org/html/rfc793#section-3.1
            fmt, args = "!4s4sHH", (PROTO_TCP, len(self))
        else:
            # https://tools.ietf.org/html/rfc2460#section-8.1
            fmt, args = "!16s16sLL", (len(self), PROTO_TCP)
        pseudo_header = struct.pack(fmt, ip.sip, ip.dip, *args)
        self.chksum = Header.chksum(pseudo_header + self.bytez)


class Packet(object):
    def __init__(self, dmac, smac, sip, dip, sport, dport):
        IP = IPv4 if VERSION == 4 else IPv6

        self.eth = Ethernet.from_args(dmac=dmac, smac=smac, ethertype=ETH_P_IP if VERSION == 4 else ETH_P_IPV6,)
        self.ip = IP.from_args(sip=sip, dip=dip)
        self.tcp = TCP.from_args(sport=sport, dport=dport)

        if VERSION == 4:
            self.ip.calc_chksum()
        self.tcp.calc_chksum(self.ip)

    def __len__(self):
        return len(self.bytez)

    @property
    def bytez(self):
        return bytes(self.eth.bytez + self.ip.bytez + self.tcp.bytez)

    @property
    def hex(self):
        return binascii.hexlify(self.bytez)


class Port(object):
    """Context manager used for securing a TCP source port for raw packets."""

    def __init__(self):
        self.af = socket.AF_INET if VERSION == 4 else socket.AF_INET6
        self.sock = None
        self.num = None

    def __del__(self):
        self.close()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def open(self):
        if self.sock is None:
            self.sock = socket.socket(self.af, socket.SOCK_STREAM)
            self.sock.bind(("", 0))
            self.num = self.sock.getsockname()[1]


class VRF(object):
    """Context manager used for sourcing packets from a kernel namespace."""

    def __init__(self, name="default"):
        # eos prepends vrf name with 'ns-' in kernel namespace
        if name != "default" and not name.startswith("ns-"):
            name = "ns-" + name
        self.name = name
        self.vrf = self.path(name=self.name)
        self.out = None

    def __delete__(self):
        self.close()

    def __enter__(self):
        self.open()

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()

    def close(self):
        if self.out is not None:
            self.setns(self.out)
            self.out.close()
            self.out = None

    def open(self):
        # store the original kernel namespace for context exit
        self.out = open(self.path(pid=os.getpid()))

        try:
            with open(self.vrf) as ns:
                self.setns(ns)
        except IOError:
            raise IOError("No such VRF: '{0}'".format(self.name))

    def path(self, name=None, pid=None):
        if name:
            return "/var/run/netns/{0}".format(name)
        elif pid:
            return "/proc/{0}/ns/net".format(pid)

    def setns(self, ns):
        try:
            return LIBC.setns(ns.fileno(), CLONE_NEWNET)
        except AttributeError as e:
            raise AttributeError(e.message)


def _subprocess(args, raise_for_status=True):
    p = sp.Popen(args, stdout=sp.PIPE, stderr=sp.PIPE, shell=True)
    stdout, stderr = p.communicate()
    if p.returncode and raise_for_status:
        cmd = args.split()[0]
        raise sp.CalledProcessError("Command '%s' returned non-zero exit status %d" % (cmd, p.returncode))
    return stdout, stderr


def attach_bpf(eth, ip, tcp, sock):
    """Attach a filter to a raw socket.

    Args:
        eth (Ethernet): A crafted Ethernet header.
        ip: A crafted IPv4 or IPv6 header.
        tcp (TCP): A crafted TCP header.
        sock (socket): A raw socket.

    """

    def hexlify_32(bytez, dwords=1):
        """Turn a bytes object into a list of 32-bit integers.

        Args:
            bytez (bytes): A bytes object. Interpreted as an arbitrarily wide
                unsigned big-endian integer.
            dwords (int, optional): Width of the integer in dwords of 32 bits.
                Defaults to 1.

        Returns:
            list: A list of 32-bit portions, high to low, of the bytes object
                after interpretation as an unsigned big-endian integer.

        """

        result, num = [], int(binascii.hexlify(bytez), 16)
        for _ in range(max(dwords, 1)):
            result.append(num & 0xFFFFFFFF)
            num >>= 32
        return result[::-1]

    smac_hi, smac_lo = hexlify_32(eth.smac, 2)
    dmac_hi, dmac_lo = hexlify_32(eth.dmac, 2)

    if VERSION == 4:
        (dip,) = hexlify_32(ip.dip)
        (sip,) = hexlify_32(ip.sip)

        # fmt: off
        # #!/usr/bin/env bash
        # export E="ether src DMAC && ether dst SMAC"
        # export I="ip && src DIP && dst SIP"
        # export T="tcp && src port DPORT && dst port SPORT"
        # paste -d"\n" \
        #     <(tcpdump -d "${E} && ${I} && ${T}" | sed -e 's/^/# /') \
        #     <(tcpdump -dd "${E} && ${I} && ${T}" | sed -e 's/{ /(/;s/ }/)/')
        instructions = [
            # # smac matches our dmac
            # (0x20, 0, 0, 0x00000008),  # (000) ld    [8]
            # (0x15, 0, 22, dmac_lo),    # (001) jeq   SMAC 31-0     jt 2  jf 24
            # (0x28, 0, 0, 0x00000006),  # (002) ldh   [6]
            # (0x15, 0, 20, dmac_hi),    # (003) jeq   SMAC 47-32    jt 4  jf 24
            # dmac matches our smac
            (0x20, 0, 0, 0x00000002),  # (004) ld    [2]
            (0x15, 0, 18, smac_lo),    # (005) jeq   DMAC 31-0     jt 6  jf 24
            (0x28, 0, 0, 0x00000000),  # (006) ldh   [0]
            (0x15, 0, 16, smac_hi),    # (007) jeq   DMAC 47-32    jt 8  jf 24
            # ethertype is ipv4
            (0x28, 0, 0, 0x0000000C),  # (008) ldh   [12]
            (0x15, 0, 14, ETH_P_IP),   # (009) jeq   #0x800        jt 10 jf 24
            # sip matches our dip
            (0x20, 0, 0, 0x0000001A),  # (010) ld    [26]
            (0x15, 0, 12, dip),        # (011) jeq   SIP           jt 12 jf 24
            # dip matches our sip
            (0x20, 0, 0, 0x0000001E),  # (012) ld    [30]
            (0x15, 0, 10, sip),        # (013) jeq   DIP           jt 14 jf 24
            # protocol is tcp
            (0x30, 0, 0, 0x00000017),  # (014) ldb   [23]
            (0x15, 0, 8, PROTO_TCP),   # (015) jeq   #0x6          jt 16 jf 24
            # fragment offset is 0
            (0x28, 0, 0, 0x00000014),  # (016) ldh   [20]
            (0x45, 6, 0, 0x00001FFF),  # (017) jset  #0x1fff       jt 24 jf 18
            # sport matches our dport,
            # dport matches our sport
            (0xb1, 0, 0, ETH_HLEN),    # (018) ldx   4*([14]&0xf)
            (0x48, 0, 0, 0x0000000E),  # (019) ldh   [x + 14]
            (0x15, 0, 3, tcp.dport),   # (020) jeq   SPORT         jt 21 jf 24
            (0x48, 0, 0, 0x00000010),  # (021) ldh   [x + 16]
            (0x15, 0, 1, tcp.sport),   # (022) jeq   DPORT         jt 23 jf 24
            # success/failure
            (0x6, 0, 0, 0x00040000),   # (023) ret   #262144
            (0x6, 0, 0, 0x00000000),   # (024) ret   #0
        ]
        # fmt: on
    else:  # if VERSION == 6:
        sip_hi1, sip_hi2, sip_lo1, sip_lo2 = hexlify_32(ip.sip, 4)
        dip_hi1, dip_hi2, dip_lo1, dip_lo2 = hexlify_32(ip.dip, 4)

        # fmt: off
        # #!/usr/bin/env bash
        # export E="ether src DMAC && ether dst SMAC"
        # export I="ip6 && src DIP && dst SIP"
        # export T="tcp && src port DPORT && dst port SPORT"
        # paste -d"\n" \
        #     <(tcpdump -d "${E} && ${I} && ${T}" | sed -e 's/^/# /') \
        #     <(tcpdump -dd "${E} && ${I} && ${T}" | sed -e 's/{ /(/;s/ }/)/')
        instructions = [
            # # smac matches our dmac
            # (0x20, 0, 0, 0x00000008),   # (000) ld   [8]
            # (0x15, 0, 31, smac_lo),     # (001) jeq  SMAC 31-0   jt 2  jf 33
            # (0x28, 0, 0, 0x00000006),   # (002) ldh  [6]
            # (0x15, 0, 29, smac_hi),     # (003) jeq  SMAC 47-32  jt 4  jf 33
            # (0x20, 0, 0, 0x00000002),   # (004) ld   [2]
            # dmac matches our smac
            (0x15, 0, 27, dmac_lo),     # (005) jeq  DMAC 31-0   jt 6  jf 33
            (0x28, 0, 0, 0x00000000),   # (006) ldh  [0]
            (0x15, 0, 25, dmac_hi),     # (007) jeq  DMAC 47-32  jt 8  jf 33
            (0x28, 0, 0, 0x0000000C),   # (008) ldh  [12]
            # ethertype is ipv6
            (0x15, 0, 23, ETH_P_IPV6),  # (009) jeq  #0x86dd     jt 10 jf 33
            (0x20, 0, 0, 0x00000016),   # (010) ld   [22]
            # sip matches our dip
            (0x15, 0, 21, dip_hi1),     # (011) jeq  SIP 127-96  jt 12 jf 33
            (0x20, 0, 0, 0x0000001A),   # (012) ld   [26]
            (0x15, 0, 19, dip_hi2),     # (013) jeq  SIP 95-64   jt 14 jf 33
            (0x20, 0, 0, 0x0000001E),   # (014) ld   [30]
            (0x15, 0, 17, dip_lo1),     # (015) jeq  SIP 63-32   jt 16 jf 33
            (0x20, 0, 0, 0x00000022),   # (016) ld   [34]
            (0x15, 0, 15, dip_lo2),     # (017) jeq  SIP 31-0    jt 18 jf 33
            (0x20, 0, 0, 0x00000026),   # (018) ld   [38]
            # dip matches our sip
            (0x15, 0, 13, sip_hi1),     # (019) jeq  DIP 127-96  jt 20 jf 33
            (0x20, 0, 0, 0x0000002A),   # (020) ld   [42]
            (0x15, 0, 11, sip_hi2),     # (021) jeq  DIP 95-64   jt 22 jf 33
            (0x20, 0, 0, 0x0000002E),   # (022) ld   [46]
            (0x15, 0, 9, sip_lo1),      # (023) jeq  DIP 63-32   jt 24 jf 33
            (0x20, 0, 0, 0x00000032),   # (024) ld   [50]
            (0x15, 0, 7, sip_lo2),      # (025) jeq  DIP 31-0    jt 26 jf 33
            # protocol is tcp
            (0x30, 0, 0, 0x00000014),   # (026) ldb  [20]
            (0x15, 0, 5, PROTO_TCP),    # (027) jeq  #0x6        jt 28 jf 33
            # sport matches our dport
            (0x28, 0, 0, 0x00000036),   # (028) ldh  [54]
            (0x15, 0, 3, tcp.dport),    # (029) jeq  SPORT       jt 30 jf 33
            # dport matches our sport
            (0x28, 0, 0, 0x00000038),   # (030) ldh  [56]
            (0x15, 0, 1, tcp.sport),    # (031) jeq  DPORT       jt 32 jf 33
            # success/failure
            (0x6, 0, 0, 0x00040000),    # (032) ret  #262144
            (0x6, 0, 0, 0x00000000),    # (033) ret  #0
        ]
        # fmt: on

    packed = "".join(struct.pack("HBBL", *inst) for inst in instructions)
    string_buffer = create_string_buffer(packed)
    address = addressof(string_buffer)
    bpf_program = struct.pack("HL", len(instructions), address)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_ATTACH_FILTER, bpf_program)


def nexthop_meta(nhip):
    """Determine details of our connection to the nexthop router.

    Args:
        nhip (str): The IP address of the nexthop router.

    Returns:
        tuple: 4-element tuple containing:
            intf (str): Our connected interface to the nexthop router.
            dmac (str): The (destination) MAC address of the nexthop router.
            smac (str): The (source) MAC address of our connected interface.
            sip (str): The (source) IP address of our connected interface.

    """

    mask = 32 if VERSION == 4 else 128
    args = (
        NEXTHOP_META.strip()
        .replace("__VERSION__", str(VERSION))
        .replace("__NHIP__", nhip)
        .replace("__MASK__", str(mask))
        .replace("\n", "; ")
    )
    try:
        stdout, _ = _subprocess(args)
        intf, dmac, smac, sip = stdout.split()
    except ValueError:
        raise ValueError("Unable to parse 'ip' command output")
    return intf, dmac, smac, sip


def pre_ping(nhip):
    """Populate the ARP table with the IP address of the nexthop router.

    Args:
        nhip (str): The IP address of the nexthop router.

    """

    args = "ping -%s -c1 %s" % (VERSION, nhip)
    _subprocess(args, raise_for_status=False)


def send_recv(pkt, intf):
    """Transmit a TCP `pkt` out the specified `intf` and wait for
    a response. Retransmit the `pkt` if no response is received.

    Args:
        pkt (Packet): A crafted TCP packet.
        intf (str): The switch interface that the raw socket will
            bind to and from which packets will be sent and received.

    Raises:
        IOError: If a socket error is encountered.

    Returns:
        bool: True if the response contains a SYN-ACK, else False.

    """

    proto = socket.htons(ETH_P_IP if VERSION == 4 else ETH_P_IPV6)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, proto)
    attach_bpf(pkt.eth, pkt.ip, pkt.tcp, sock)
    sock.bind((intf, 0))

    result, retransmit = None, 0
    try:
        while result is None and retransmit < 3:
            sock.send(pkt.bytez)
            retransmit_timeout = time.time() + (1.0 / 3)

            while True:
                timeout = retransmit_timeout - time.time()
                if timeout < 0:
                    break

                can_recv, _, _ = select.select([sock], [], [], timeout)
                if not can_recv:
                    continue

                try:
                    buff = sock.recv(65535)
                except sock.error as e:
                    raise IOError("Socket error: {0}".format(e))

                offset = 0
                try:
                    rcv_eth = Ethernet.from_buffer_copy(buff)
                    offset += len(rcv_eth)

                    IP = IPv4 if VERSION == 4 else IPv6
                    rcv_ip = IP.from_buffer_copy(buff, offset)
                    offset += len(rcv_ip)

                    rcv_tcp = TCP.from_buffer_copy(buff, offset)
                    offset += len(rcv_tcp)

                    if rcv_tcp.flags == TCP.FLAGS["SYN"] | TCP.FLAGS["ACK"]:
                        pkt.tcp.seq = rcv_tcp.ack
                        pkt.tcp.flags = TCP.FLAGS["RST"]
                        pkt.tcp.calc_chksum(pkt.ip)
                        sock.send(pkt.bytez)
                        result = True
                    if rcv_tcp.flags == TCP.FLAGS["RST"] | TCP.FLAGS["ACK"]:
                        result = False
                    break
                except ValueError:
                    # frame is too short
                    continue

            retransmit += 1
    finally:
        sock.close()

    return result or False


def ip_version(ip):
    for version, af in (4, socket.AF_INET), (6, socket.AF_INET6):
        try:
            socket.inet_pton(af, ip)
            return version
        except socket.error:
            continue
    raise ValueError("IP address invalid")


def scan(dip, dport, nhip, vrf="default"):
    try:
        global VERSION
        VERSION = ip_version(dip)
        if VERSION != ip_version(nhip):
            raise ValueError("DIP and NHIP version mismatch")

        with VRF(name=vrf):
            pre_ping(nhip)
            try:
                intf, dmac, smac, sip = nexthop_meta(nhip)
            except ValueError:
                return False
            with Port() as sport:
                pkt = Packet(dmac=dmac, smac=smac, sip=sip, dip=dip, sport=sport.num, dport=dport,)
                result = send_recv(pkt, intf)

    except Exception as e:
        raise RuntimeError(e)
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(prog="synscan", description="")
    parser.add_argument(
        "-v", "--version", action="version", version="%(prog)s {0}".format(__version__),
    )
    synscan_group = parser.add_argument_group("synscan arguments")
    synscan_group.add_argument(
        "dip", type=str, help="IP address of the target device (required)", metavar="IP",
    )
    synscan_group.add_argument(
        "dport", type=int, help="TCP port of the target service (required)", metavar="PORT",
    )
    synscan_group.add_argument(
        "-n",
        "--nexthop",
        default=None,
        type=str,
        required=True,
        help="next gateway to which packets should be forwarded (required)",
        metavar="IP",
        dest="nhip",
    )
    synscan_group.add_argument(
        "-V",
        "--vrf",
        default="default",
        type=str,
        required=False,
        help="VRF from which packets should originate",
        metavar="VRF",
        dest="vrf",
    )
    args = parser.parse_args()

    try:
        result = scan(args.dip, args.dport, args.nhip, args.vrf)
        sys.exit(0 if result else 1)
    except RuntimeError as e:
        print(e, file=sys.stderr)
        sys.exit(127)
