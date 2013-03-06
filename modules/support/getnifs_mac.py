#!/usr/bin/python
 
# Based on getifaddrs.py from pydlnadms [http://code.google.com/p/pydlnadms/].
# Ported to Mac OS X (tested only on Mountain Lion 10.8.2) through updating
# the structures.
 
from socket import AF_INET, AF_INET6, inet_ntop
from ctypes import (
    Structure, Union, POINTER,
    pointer, get_errno, cast,
    c_ushort, c_byte, c_void_p, c_char_p, c_uint, c_int, c_uint8, c_char, c_uint16, c_uint32
)
import ctypes.util
import ctypes
 
class struct_sockaddr(Structure):
    _fields_ = [
            ('sa_len', c_uint8),
            ('sa_family', c_uint8),
            ('sa_data', c_byte * 14)
        ]
 
class struct_sockaddr_in(Structure):
    _fields_ = [
            ('sin_len', c_uint8),
            ('sin_family', c_uint8),
            ('sin_port', c_uint16),
            ('sin_addr', c_byte * 4),
            ('sin_zero', c_char * 8)
        ]
 
class struct_sockaddr_in6(Structure):
    _fields_ = [
            ('sin6_len', c_uint8),
            ('sin6_family', c_uint8),
            ('sin6_port', c_uint16),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr', c_byte * 16),
            ('sin6_scope_id', c_uint32)
        ]
 
class struct_ifaddrs(Structure):
    pass

struct_ifaddrs._fields_ = [
        ('ifa_next', POINTER(struct_ifaddrs)),
        ('ifa_name', c_char_p),
        ('ifa_flags', c_uint),
        ('ifa_addr', POINTER(struct_sockaddr)),
        ('ifa_netmask', POINTER(struct_sockaddr)),
        ('ifa_dstaddr', POINTER(struct_sockaddr)),
        ('ifa_data', c_void_p)
    ]
 
libc = ctypes.CDLL(ctypes.util.find_library('c'))
 
def ifap_iter(ifap):
    ifa = ifap.contents
    while True:
        yield ifa
        if not ifa.ifa_next:
            break
        ifa = ifa.ifa_next.contents
 
def getfamaddr(sa):
    family = sa.sa_family
    addr = None
    if family == AF_INET:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in)).contents
        addr = inet_ntop(family, sa.sin_addr)
    elif family == AF_INET6:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in6)).contents
        addr = inet_ntop(family, sa.sin6_addr)
    return family, addr
 
class NetworkInterface(object):
    def __init__(self, name):
        self.name = name
        self.index = libc.if_nametoindex(name)
        self.addresses = {}
 
    def __str__(self):
        return "%s [index=%d, IPv4=%s, IPv6=%s]" % (
            self.name, self.index,
            self.addresses.get(AF_INET),
            self.addresses.get(AF_INET6))
 
def get_network_interfaces():
    ifap = POINTER(struct_ifaddrs)()
    result = libc.getifaddrs(pointer(ifap))
    if result != 0:
        raise OSError(get_errno())
    del result
    try:
        retval = {}
        for ifa in ifap_iter(ifap):
            name = ifa.ifa_name
            i = retval.get(name)
            if not i:
                i = retval[name] = NetworkInterface(name)
            family, addr = getfamaddr(ifa.ifa_addr.contents)
            if addr:
                i.addresses[family] = addr
        return retval.values()
    finally:
        libc.freeifaddrs(ifap)
 
if __name__ == '__main__':
    print [str(ni) for ni in get_network_interfaces()]