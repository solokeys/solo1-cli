"""
kdf_calc.py - a library for calculating hash by KDF

Copyright (C) 2018  Free Software Initiative of Japan
Author: NIIBE Yutaka <gniibe@fsij.org>

This file is a part of Gnuk, a GnuPG USB Token implementation.

Gnuk is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Gnuk is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from cffi import FFI

DEF_gcry_kdf_derive="""
typedef unsigned int gpg_error_t;
gpg_error_t gcry_kdf_derive (const void *passphrase, size_t passphraselen,
                             int algo, int subalgo, const void *salt,
                             size_t saltlen, unsigned long iterations,
                             size_t keysize, void *keybuffer);
"""

GCRY_KDF_ITERSALTED_S2K = 19
GCRY_MD_SHA256  = 8

def kdf_calc(pw_string, salt_byte, iterations):
    ffi = FFI()
    ffi.cdef(DEF_gcry_kdf_derive)
    libgcrypt = ffi.dlopen("libgcrypt.so.20")
    if isinstance(pw_string, str):
        pw_byte = pw_string.encode('UTF-8')
    else:
        pw_byte = pw_string
    pw=ffi.new("char []", pw_byte)
    salt = ffi.new("char []", salt_byte)
    kb = ffi.new("char []", 32)
    r = libgcrypt.gcry_kdf_derive(pw, len(pw_string), GCRY_KDF_ITERSALTED_S2K,
                                  GCRY_MD_SHA256, salt, 8, iterations, 32, kb)
    if r != 0:
        raise ValueError("libgcrypt error", r)
    return ffi.unpack(kb, 32)
