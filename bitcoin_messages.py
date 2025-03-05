#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bitcoin test framework primitive and message structures

CBlock, CTransaction, CBlockHeader, CTxIn, CTxOut, etc....:
    data structures that should map to corresponding structures in
    bitcoin/primitives

ser_*, deser_*: functions that handle serialization/deserialization.

Classes use __slots__ to ensure extraneous attributes aren't accidentally added
by tests, compromising their intended effect.
"""
import copy
import hashlib
from io import BytesIO
import math
import time


def assert_equal(thing1, thing2, *args):
    if thing1 != thing2 or any(thing1 != arg for arg in args):
        raise AssertionError("not(%s)" % " == ".join(str(arg) for arg in (thing1, thing2) + args))


COIN = 100000000  # 1 btc in satoshis
MAX_MONEY = 21000000 * COIN

MSG_TX = 1
MSG_BLOCK = 2
MSG_FILTERED_BLOCK = 3
MSG_CMPCT_BLOCK = 4
MSG_WTX = 5
MSG_WITNESS_FLAG = 1 << 30
MSG_TYPE_MASK = 0xffffffff >> 2
MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG

WITNESS_SCALE_FACTOR = 4


def sha256(s):
    return hashlib.sha256(s).digest()


def hash256(s):
    return sha256(sha256(s))


def ser_compact_size(l):
    r = b""
    if l < 253:
        r = l.to_bytes(1, "little")
    elif l < 0x10000:
        r = (253).to_bytes(1, "little") + l.to_bytes(2, "little")
    elif l < 0x100000000:
        r = (254).to_bytes(1, "little") + l.to_bytes(4, "little")
    else:
        r = (255).to_bytes(1, "little") + l.to_bytes(8, "little")
    return r


def deser_compact_size(f):
    nit = int.from_bytes(f.read(1), "little")
    if nit == 253:
        nit = int.from_bytes(f.read(2), "little")
    elif nit == 254:
        nit = int.from_bytes(f.read(4), "little")
    elif nit == 255:
        nit = int.from_bytes(f.read(8), "little")
    return nit


def deser_string(f):
    nit = deser_compact_size(f)
    return f.read(nit)


def ser_string(s):
    return ser_compact_size(len(s)) + s


def deser_uint256(f):
    return int.from_bytes(f.read(32), 'little')


def ser_uint256(u):
    return u.to_bytes(32, 'little')


def uint256_from_str(s):
    return int.from_bytes(s[:32], 'little')


def uint256_from_compact(c):
    nbytes = (c >> 24) & 0xFF
    v = (c & 0xFFFFFF) << (8 * (nbytes - 3))
    return v


# deser_function_name: Allow for an alternate deserialization function on the
# entries in the vector.
def deser_vector(f, c, deser_function_name=None):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = c()
        if deser_function_name:
            getattr(t, deser_function_name)(f)
        else:
            t.deserialize(f)
        r.append(t)
    return r


# ser_function_name: Allow for an alternate serialization function on the
# entries in the vector (we use this for serializing the vector of transactions
# for a witness block).
def ser_vector(l, ser_function_name=None):
    r = ser_compact_size(len(l))
    for i in l:
        if ser_function_name:
            r += getattr(i, ser_function_name)()
        else:
            r += i.serialize()
    return r


def deser_uint256_vector(f):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_uint256(f)
        r.append(t)
    return r


def ser_uint256_vector(l):
    r = ser_compact_size(len(l))
    for i in l:
        r += ser_uint256(i)
    return r


def deser_string_vector(f):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def ser_string_vector(l):
    r = ser_compact_size(len(l))
    for sv in l:
        r += ser_string(sv)
    return r


def from_hex(obj, hex_string):
    """Deserialize from a hex string representation (e.g. from RPC)

    Note that there is no complementary helper like e.g. `to_hex` for the
    inverse operation. To serialize a message object to a hex string, simply
    use obj.serialize().hex()"""
    obj.deserialize(BytesIO(bytes.fromhex(hex_string)))
    return obj


def tx_from_hex(hex_string):
    """Deserialize from hex string to a transaction object"""
    return from_hex(CTransaction(), hex_string)


# like from_hex, but without the hex part
def from_binary(cls, stream):
    """deserialize a binary stream (or bytes object) into an object"""
    # handle bytes object by turning it into a stream
    was_bytes = isinstance(stream, bytes)
    if was_bytes:
        stream = BytesIO(stream)
    obj = cls()
    obj.deserialize(stream)
    if was_bytes:
        assert len(stream.read()) == 0
    return obj


class COutPoint:
    __slots__ = ("hash", "n")

    def __init__(self, hash=0, n=0):
        self.hash = hash
        self.n = n

    def deserialize(self, f):
        self.hash = deser_uint256(f)
        self.n = int.from_bytes(f.read(4), "little")

    def serialize(self):
        r = b""
        r += ser_uint256(self.hash)
        r += self.n.to_bytes(4, "little")
        return r

    def __repr__(self):
        return "COutPoint(hash=%064x n=%i)" % (self.hash, self.n)


class CTxIn:
    __slots__ = ("nSequence", "prevout", "scriptSig")

    def __init__(self, outpoint=None, scriptSig=b"", nSequence=0):
        if outpoint is None:
            self.prevout = COutPoint()
        else:
            self.prevout = outpoint
        self.scriptSig = scriptSig
        self.nSequence = nSequence

    def deserialize(self, f):
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = int.from_bytes(f.read(4), "little")

    def serialize(self):
        r = b""
        r += self.prevout.serialize()
        r += ser_string(self.scriptSig)
        r += self.nSequence.to_bytes(4, "little")
        return r

    def __repr__(self):
        return "CTxIn(prevout=%s scriptSig=%s nSequence=%i)" \
            % (repr(self.prevout), self.scriptSig.hex(),
               self.nSequence)


class CTxOut:
    __slots__ = ("nValue", "scriptPubKey")

    def __init__(self, nValue=0, scriptPubKey=b""):
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey

    def deserialize(self, f):
        self.nValue = int.from_bytes(f.read(8), "little", signed=True)
        self.scriptPubKey = deser_string(f)

    def serialize(self):
        r = b""
        r += self.nValue.to_bytes(8, "little", signed=True)
        r += ser_string(self.scriptPubKey)
        return r

    def __repr__(self):
        return "CTxOut(nValue=%i.%08i scriptPubKey=%s)" \
            % (self.nValue // COIN, self.nValue % COIN,
               self.scriptPubKey.hex())


class CScriptWitness:
    __slots__ = ("stack",)

    def __init__(self):
        # stack is a vector of strings
        self.stack = []

    def __repr__(self):
        return "CScriptWitness(%s)" % \
               (",".join([x.hex() for x in self.stack]))

    def is_null(self):
        if self.stack:
            return False
        return True


class CTxInWitness:
    __slots__ = ("scriptWitness",)

    def __init__(self):
        self.scriptWitness = CScriptWitness()

    def deserialize(self, f):
        self.scriptWitness.stack = deser_string_vector(f)

    def serialize(self):
        return ser_string_vector(self.scriptWitness.stack)

    def __repr__(self):
        return repr(self.scriptWitness)

    def is_null(self):
        return self.scriptWitness.is_null()


class CTxWitness:
    __slots__ = ("vtxinwit",)

    def __init__(self):
        self.vtxinwit = []

    def deserialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].deserialize(f)

    def serialize(self):
        r = b""
        # This is different than the usual vector serialization --
        # we omit the length of the vector, which is required to be
        # the same length as the transaction's vin vector.
        for x in self.vtxinwit:
            r += x.serialize()
        return r

    def __repr__(self):
        return "CTxWitness(%s)" % \
               (';'.join([repr(x) for x in self.vtxinwit]))

    def is_null(self):
        for x in self.vtxinwit:
            if not x.is_null():
                return False
        return True


class CTransaction:
    __slots__ = ("hash", "nLockTime", "version", "sha256", "vin", "vout",
                 "wit")

    def __init__(self, tx=None):
        if tx is None:
            self.version = 2
            self.vin = []
            self.vout = []
            self.wit = CTxWitness()
            self.nLockTime = 0
            self.sha256 = None
            self.hash = None
        else:
            self.version = tx.version
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.sha256 = tx.sha256
            self.hash = tx.hash
            self.wit = copy.deepcopy(tx.wit)

    def deserialize(self, f):
        self.version = int.from_bytes(f.read(4), "little")
        self.vin = deser_vector(f, CTxIn)
        flags = 0
        if len(self.vin) == 0:
            flags = int.from_bytes(f.read(1), "little")
            # Not sure why flags can't be zero, but this
            # matches the implementation in bitcoind
            if (flags != 0):
                self.vin = deser_vector(f, CTxIn)
                self.vout = deser_vector(f, CTxOut)
        else:
            self.vout = deser_vector(f, CTxOut)
        if flags != 0:
            self.wit.vtxinwit = [CTxInWitness() for _ in range(len(self.vin))]
            self.wit.deserialize(f)
        else:
            self.wit = CTxWitness()
        self.nLockTime = int.from_bytes(f.read(4), "little")
        self.sha256 = None
        self.hash = None

    def serialize_without_witness(self):
        r = b""
        r += self.version.to_bytes(4, "little")
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += self.nLockTime.to_bytes(4, "little")
        return r

    # Only serialize with witness when explicitly called for
    def serialize_with_witness(self):
        flags = 0
        if not self.wit.is_null():
            flags |= 1
        r = b""
        r += self.version.to_bytes(4, "little")
        if flags:
            dummy = []
            r += ser_vector(dummy)
            r += flags.to_bytes(1, "little")
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        if flags & 1:
            if (len(self.wit.vtxinwit) != len(self.vin)):
                # vtxinwit must have the same length as vin
                self.wit.vtxinwit = self.wit.vtxinwit[:len(self.vin)]
                for _ in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(CTxInWitness())
            r += self.wit.serialize()
        r += self.nLockTime.to_bytes(4, "little")
        return r

    # Regular serialization is with witness -- must explicitly
    # call serialize_without_witness to exclude witness data.
    def serialize(self):
        return self.serialize_with_witness()

    def getwtxid(self):
        return hash256(self.serialize())[::-1].hex()

    # Recalculate the txid (transaction hash without witness)
    def rehash(self):
        self.sha256 = None
        self.calc_sha256()
        return self.hash

    # We will only cache the serialization without witness in
    # self.sha256 and self.hash -- those are expected to be the txid.
    def calc_sha256(self, with_witness=False):
        if with_witness:
            # Don't cache the result, just return it
            return uint256_from_str(hash256(self.serialize_with_witness()))

        if self.sha256 is None:
            self.sha256 = uint256_from_str(hash256(self.serialize_without_witness()))
        self.hash = hash256(self.serialize_without_witness())[::-1].hex()

    def is_valid(self):
        self.calc_sha256()
        for tout in self.vout:
            if tout.nValue < 0 or tout.nValue > 21000000 * COIN:
                return False
        return True

    # Calculate the transaction weight using witness and non-witness
    # serialization size (does NOT use sigops).
    def get_weight(self):
        with_witness_size = len(self.serialize_with_witness())
        without_witness_size = len(self.serialize_without_witness())
        return (WITNESS_SCALE_FACTOR - 1) * without_witness_size + with_witness_size

    def get_vsize(self):
        return math.ceil(self.get_weight() / WITNESS_SCALE_FACTOR)

    def __repr__(self):
        return "CTransaction(version=%i vin=%s vout=%s wit=%s nLockTime=%i)" \
            % (self.version, repr(self.vin), repr(self.vout), repr(self.wit), self.nLockTime)


class CBlockHeader:
    __slots__ = ("hash", "hashMerkleRoot", "hashPrevBlock", "nBits", "nNonce",
                 "nTime", "nVersion", "sha256")

    def __init__(self, header=None):
        if header is None:
            self.set_null()
        else:
            self.nVersion = header.nVersion
            self.hashPrevBlock = header.hashPrevBlock
            self.hashMerkleRoot = header.hashMerkleRoot
            self.nTime = header.nTime
            self.nBits = header.nBits
            self.nNonce = header.nNonce
            self.sha256 = header.sha256
            self.hash = header.hash
            self.calc_sha256()

    def set_null(self):
        self.nVersion = 4
        self.hashPrevBlock = 0
        self.hashMerkleRoot = 0
        self.nTime = 0
        self.nBits = 0
        self.nNonce = 0
        self.sha256 = None
        self.hash = None

    def deserialize(self, f):
        self.nVersion = int.from_bytes(f.read(4), "little", signed=True)
        self.hashPrevBlock = deser_uint256(f)
        self.hashMerkleRoot = deser_uint256(f)
        self.nTime = int.from_bytes(f.read(4), "little")
        self.nBits = int.from_bytes(f.read(4), "little")
        self.nNonce = int.from_bytes(f.read(4), "little")
        self.sha256 = None
        self.hash = None

    def serialize(self):
        r = b""
        r += self.nVersion.to_bytes(4, "little", signed=True)
        r += ser_uint256(self.hashPrevBlock)
        r += ser_uint256(self.hashMerkleRoot)
        r += self.nTime.to_bytes(4, "little")
        r += self.nBits.to_bytes(4, "little")
        r += self.nNonce.to_bytes(4, "little")
        return r

    def calc_sha256(self):
        if self.sha256 is None:
            r = b""
            r += self.nVersion.to_bytes(4, "little", signed=True)
            r += ser_uint256(self.hashPrevBlock)
            r += ser_uint256(self.hashMerkleRoot)
            r += self.nTime.to_bytes(4, "little")
            r += self.nBits.to_bytes(4, "little")
            r += self.nNonce.to_bytes(4, "little")
            self.sha256 = uint256_from_str(hash256(r))
            self.hash = hash256(r)[::-1].hex()

    def rehash(self):
        self.sha256 = None
        self.calc_sha256()
        return self.sha256

    def __repr__(self):
        return "CBlockHeader(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x)" \
            % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot,
               time.ctime(self.nTime), self.nBits, self.nNonce)

BLOCK_HEADER_SIZE = len(CBlockHeader().serialize())
assert_equal(BLOCK_HEADER_SIZE, 80)

class CBlock(CBlockHeader):
    __slots__ = ("vtx",)

    def __init__(self, header=None):
        super().__init__(header)
        self.vtx = []

    def deserialize(self, f):
        super().deserialize(f)
        self.vtx = deser_vector(f, CTransaction)

    def serialize(self, with_witness=True):
        r = b""
        r += super().serialize()
        if with_witness:
            r += ser_vector(self.vtx, "serialize_with_witness")
        else:
            r += ser_vector(self.vtx, "serialize_without_witness")
        return r

    # Calculate the merkle root given a vector of transaction hashes
    @classmethod
    def get_merkle_root(cls, hashes):
        while len(hashes) > 1:
            newhashes = []
            for i in range(0, len(hashes), 2):
                i2 = min(i+1, len(hashes)-1)
                newhashes.append(hash256(hashes[i] + hashes[i2]))
            hashes = newhashes
        return uint256_from_str(hashes[0])

    def calc_merkle_root(self):
        hashes = []
        for tx in self.vtx:
            tx.calc_sha256()
            hashes.append(ser_uint256(tx.sha256))
        return self.get_merkle_root(hashes)

    def calc_witness_merkle_root(self):
        # For witness root purposes, the hash of the
        # coinbase, with witness, is defined to be 0...0
        hashes = [ser_uint256(0)]

        for tx in self.vtx[1:]:
            # Calculate the hashes with witness data
            hashes.append(ser_uint256(tx.calc_sha256(True)))

        return self.get_merkle_root(hashes)

    def is_valid(self):
        self.calc_sha256()
        target = uint256_from_compact(self.nBits)
        if self.sha256 > target:
            return False
        for tx in self.vtx:
            if not tx.is_valid():
                return False
        if self.calc_merkle_root() != self.hashMerkleRoot:
            return False
        return True

    def solve(self):
        self.rehash()
        target = uint256_from_compact(self.nBits)
        while self.sha256 > target:
            self.nNonce += 1
            self.rehash()

    # Calculate the block weight using witness and non-witness
    # serialization size (does NOT use sigops).
    def get_weight(self):
        with_witness_size = len(self.serialize(with_witness=True))
        without_witness_size = len(self.serialize(with_witness=False))
        return (WITNESS_SCALE_FACTOR - 1) * without_witness_size + with_witness_size

    def __repr__(self):
        return "CBlock(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x vtx=%s)" \
            % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot,
               time.ctime(self.nTime), self.nBits, self.nNonce, repr(self.vtx))
