"""
cryptohelp module - Elliptic curves ElGamal, Diffie-Hellman and pseudoprimes

cryptohelp module provides:

    * EC ElGamal keypair generation
    * EC ElGamal symmetric key derivation
    * EC ElGamal encryption/decryption

    * EC Diffie-Hellman key setup routines

    * Random numbers n-bytes long generation
    * Random numbers in range
    * Pseudoprimes n-bytes long generation
    * Miller-Rabin test.

Reuquires ent, bigrange and ec modules.
Uses logging.log.
"""

import hashlib
import support.ent as ent
import math
import os
import struct
from ec import *
from bigrange import bigrange
from logging import *

def ec_elgamal_generate_keypair(bytes):
    """
    Generates an ElGamal keypair using ecdh_init(...).

    Input:
        bytes           The length in bytes of the prime numbers to use

    Output:
        A tuple in the form:
        (
            (EC, ECPt, ECPt),   the public key (ec, generator g, a*g)
            (EC, ECPt, int)     the private key (ec, generator g, a)
        )
    """
    ec, g, a, ag=ecdh_init(bytes)
    return ((ec, g, ag), (ec, g, a))

def ec_elgamal_derive_symm_key(el1, el2):
    """
    This routine may appear mystic and mighty, but just computes the sha384 hash
    of repr(el1) + "\\n" + repr(el2).
    The order matters.

    Input:
        el1         Intended to be an instance of ECPt, works with anything.
        el2         Same as el1.

    Output:
        The output of hashlib.sha384(...).digest().

    Remarks:
        As it regards elliptic curves ElGamal, el1=b*g and el2=ab*g.
    """
    return hashlib.sha384(repr(el1)+"\n"+repr(el2)).digest()

def ec_elgamal_encrypt(msg, pk, symmalg):
    """
    Computes a random b, derives a key from b*g and ab*g, then encrypts it using symmalg.

    Input:
        msg         Plaintext message string.
        pk          Public key: a tuple (EC, ECPt, ECPt), that is (ec, generator g, a*g)
        symmalg     A callable that accepts two arguments, the key and the message.
                    symmalg(key, msg) should output a symmetric-enciphered ciphertext.

    Output:
        A tuple (ECPt, str), where the first element is actually b*g.
    """
    ec, g, ag=pk
    b=random_with_bytes(log2(ec._p)//4)
    abg=b*ag
    bg=b*g
    k=ec_elgamal_derive_symm_key(bg, abg)

    return (bg, symmalg(k, msg))

def ec_elgamal_decrypt(ct, sk, symmalg):
    """
    Computes the shared secret, derives the key, then decrypts it using symmalg.

    Input:
        ct          Symmetrically encrypted ciphertext.
        sk          Secret key: a tuple (EC, ECPt, int), that is (ec, generator g, a)
        symmalg     A callable that accepts two arguments, the key and the message.
                    symmalg(key, msg) should output a symmetric-deciphered plaintext.

    Output:
        A string, the plaintext.
    """
    ec, g, a=sk
    bg, cry=ct
    abg=a*bg
    k=ec_elgamal_derive_symm_key(bg, abg)

    return symmalg(k, cry)

def ecdh_init(bytes):
    """
    Generates a random (pseudo)prime p using a bytes-long random string.
    Then computes random parameters a, b, c such that the elliptic curve defined with them
    is nonsingular. Then picks a generator of the rational points group with pickGenerator(...)
    and computes a random integer a.

    Input:
        bytes       The number of random bytes from which to generate the pseudoprime

    Output:
        A tuple (EC, ECPt, int, ECPt), in the order the elliptic curve, the chosen generator,
        the random integer a, a times the generator.

    Remarks:
        To generate the pseudoprime the algorithm uses millerrabin_pseudoprime_with_bytes(...).
    """
    log(LOG_INFO, "crypto", "generating a random pseudoprime")
    p=millerrabin_pseudoprime_with_bytes(bytes, 20)
    log(LOG_INFO, "crypto", "chosen {}".format(p))
    ec=None; g=None
    while ec==None or g==None:

        log(LOG_INFO, "crypto", "picking random a, b, c to define an e.c.")
        a,b,c=[random_with_bytes(2*bytes)%p for x in xrange(0,3)]

        if EC.computeDiscriminant(a,b,c,p)==0: continue

        ec=EC(a,b,c,p)
        log(LOG_INFO, "crypto", str(ec))

        log(LOG_INFO, "crypto", "looking for a generator of the rational pts group")
        g=ec.pickGenerator()

    log(LOG_INFO, "crypto", "using {} as generator".format(str(g)))
    # make sure a is really random in the range 0...#C_K, by choosing a
    # random number that uses twice the bytes of p. (#C_K ~ p+1)
    log(LOG_INFO, "crypto", "chosing a random integer a")
    a=random_with_bytes(log2(p)//4)
    ag=a*g
    log(LOG_INFO, "crypto", "chosen {}, a*g is {}".format(a, str(ag)))
    return (ec, g, a, ag)

def ecdh_reply(p,g,ag):
    """
    Generates a random integer b, then computes the shared secred ab*g.

    Input:
        p           A prime number
        g           An ECPt
        ag          An ECPt multiple of g

    Output:
        A tuple (int, ECPt, ECPt) = (b, b*g, ab*g).

    Remarks:
        This routine doesn't check whether p is (pseudo)prime, nor if g and ag
        belongs to the same elliptic curve.
    """
    # make sure a is really random in the range 0...#C_K, by choosing a
    # random number that uses twice the bytes of p. (#C_K ~ p+1)
    log(LOG_INFO, "crypto", "using the e.c. "+str(g._EC))
    log(LOG_INFO, "crypto", "using the generator "+str(g))
    log(LOG_INFO, "crypto", "a*g="+str(ag))
    log(LOG_INFO, "crypto", "chosing a random b")
    b=random_with_bytes(log2(p)//4)
    bg=b*g
    log(LOG_INFO, "crypto", "chosen {}, b*g is {}".format(b, str(bg)))
    abg=b*ag
    log(LOG_INFO, "crypto", "computed ab*g, that is "+str(abg))
    return (b, bg, abg)

def ecdh_derivekey(secret):
    """
    Actually just an alias for the sha384 digest of secret's representation.

    Input:
        secret      Intended to be an ECPt (ab*g), actually can be anything

    Output:
        A binary string, output of hashlib.sha384(...).digest().
    """
    log(LOG_INFO, "crypto", "deriving key from "+str(secret))
    retval=hashlib.sha384(repr(secret)).digest()
    log(LOG_INFO, "crypto", "the key computed is "+retval[0:24].encode("hex"))
    log(LOG_INFO, "                            "+retval[24:].encode("hex"))
    return retval

def ecdh_accept(a, bg):
    """
    Simply computes a*bg and derives a key from it with ecdh_derivekey.

    Input:
        a           An integer
        bg          ECPt, b times the generator g

    Output:
        A tuple (ECPt, str) containing ab*g and the derived key.
    """
    log(LOG_INFO, "crypto", "using bg="+str(bg))
    abg=a*bg
    log(LOG_INFO, "crypto", "computed ab*g="+str(abg))
    return (abg, ecdh_derivekey(abg))

def random_with_bytes(n):
    """
    Outputs a random integer using n random bytes from os.urandom.

    Input:
        n           The number of bytes to use

    Output:
        A random int. 0 if n<=0. If you're considering the possibility of calling this
        routine with a paramter that is <=0, ask yourself where comes the value you're
        plugging in random_with_bytes(...)...
    """
    if n<=0: return 0
    m=n//8
    l=n-8*m
    data=struct.unpack("L"*m+"B"*l, os.urandom(n))
    retval=data[0]
    for i in bigrange(1, m):
        retval|=data[i]<<(64*i)
    for i in bigrange(m, m+l):
        retval|=data[i]<<(64*m+8*i)
    return retval

def log2(n):
    """
    Computes the number of binary digits used in the representation on n.

    Input:
        n           An integer.

    Output:
        As in the description. For example, 0 -> 0, 000101010101 -> 9.
    """
    log=-1
    while n>0:
        log+=1
        n=n>>1
    return log

def random_in_range(a,b):
    """
    Computes a random number in the range [a, b[.

    Input:
        a           Lower bound.
        b           Upper bound.

    Output:
        As in the description.

    Remarks:
        If a==b, outputs a; if b<a, swaps a and b.
    """
    if a==b: return a
    if b<a:
        t=b
        b=a
        a=t
    # make sure there is a random number big enough
    delta=random_with_bytes(10*int(math.ceil(log2(b-a)/8.)))
    delta%=b-a
    return a+delta

def fermat_pseudoprime_with_bytes(n):
    """
    Picks random numbers with random_with_bytes(n) and stops when one passes Fermat's
    pseudoprimality test (ent.is_pseudoprime(...)).

    Input:
        n           The number of random bytes used to generate the random prime.

    Output:
        A pseudoprime integer.
    """
    rnd=random_with_bytes(n)

    while not ent.is_pseudoprime(rnd):
        rnd=random_with_bytes(n)
    return rnd

def millerrabin_pseudoprime_with_bytes(n,k):
    """
    Picks random numbers with random_with_bytes(n) and stops when one passes Miller-
    Rabin pseudoprimality test with k rounds.

    Input:
        n           The number of random bytes used to generate the random prime.
        k           The number of rounds in Miller-Rabin test.

    Output:
        A pseudoprime integer.
    """
    rnd=random_with_bytes(n)

    while not millerrabin(rnd, k):
        rnd=random_with_bytes(n)
    return rnd

def millerrabin(n,k):
    """
    Performs Miller-Rabin pseudoprimality test on n with k rounds. Outputs True if n 
    passes the test, otherwise false. A number passing the test is a liar prime with
    probability 2^-k.

    Input:
        n           The integer to test
        k           The number of rounds of Miller-Rabin test

    Output:
        Boolean. None if n<=1. If n<=1, probably you are testing the output of random_with_bytes
        called with bytes<1. Anyway there's an error elsewhere.
    """
    if n==2 or n==3: return True
    if n%2==0: return False
    if n<=1: return None

    def millerrabin_dec(n):
        m=n-1 # therefore n is even
        m=m>>1
        pwr=1
        while m%2==0:
            pwr+=1
            m=m>>1
        # now n-1 is written as m*2**pwr
        return (pwr, m)

    s,d=millerrabin_dec(n)
    for i in bigrange(0,k):
        a=random_in_range(2, n-2)
        x=ent.powermod(a, d, n)

        if x==1 or x==n-1: continue

        goon=False
        for j in bigrange(0, s-1):
            x=ent.powermod(x, 2, n)

            if x==1: return False
            if x==n-1:
                goon=True
                break

        if goon: continue

        return False
    return True
