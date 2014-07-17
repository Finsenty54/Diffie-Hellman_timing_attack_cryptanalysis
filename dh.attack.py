# Based on a cryptography program written for Udacity coursework

# Produces private key and decrypts message.  
# Based on counting binary 1's and 0's multiplication used in calculating key.  
# In this example, there are 26 multiplications.  
# The timing attack is a type of side channel attack.
# http://en.wikipedia.org/wiki/Timing_attack

# This is all of the public information
# of a Diffie-Hellman key exchange plus the number of multiplications
# necessary to calculate (g**b)**a mod p, given g**b where `a` is
# Alice's private key and `b` is Bob's private key
# 
# This information should be enough to determine Alice's
# private key and then decrypt the message - which is given at the
# bottom of this file
#

import string

#############
# p and g are public information
#

# 2 ** 100 - 153 is prime 
# (from http://primes.utm.edu/lists/2small/0bit.html) 
# and verified using Wolfram Alpha
p = 1267650600228229401496703205223 

# primitive root (calculated using wolfram alpha)
g = 3

#############
# g_a, g_b are both transmitted public
# and easily intercepted by a passive eavesdropper
#
# g_a = g**a mod p
# g_b = g**b mod p
 
g_a = 142621255265782287951127214876
g_b = 609743693736442153553407144551

#############
# Unfortunately, for Alice, she is using a modular
# exponentiation function and so it is possible to count the number of
# multiplications used to calculate the key

n_multiplications = 26

# binary conversion
# "{0:b}".format(10)

############################
# This eliminates the recursion in the mod_exp
# shown in lecture
# and does bitwise operations
# to speed things up a bit
# but the number of multiplications stays
# the same
def mod_exp(a, b, q):
    """return a**b % q"""
    val = 1
    mult = a
    while b > 0:
        odd = b & 1 # bitwise and
        if odd == 1:
            val = (val * mult) % q
            b -= 1
        if b == 0:
            break
        mult = (mult * mult) % q
        b = b >> 1 # bitwise divide by 2
    return val

# `count_multiplications` might be useful
# to see if you've found an exponent that
# would require the same number multiplications
# as Alice's private key
def count_multiplications(exponent):
    """return the number of multiplications
    necessary to raise a number to `exponent`"""
    bits = convert_to_bits(exponent)
    return len(bits) + sum(b for b in bits) - 2

# this is the encode function used to 
# create the cipher text found at the bottom of the file
def encode(plaintext, key):
    assert len(plaintext) <= len(key)
    return [m^k for m, k in zip(plaintext, key)]

# use this function to decrypt the ciphertext
def decode(ciphertext, key):
    assert len(ciphertext) <= len(str(key))
    return [c^k for c,k in zip(ciphertext, key)]

# is_valid returns True if the input consist of valid
# characters (numbers, upper case A-Z and lower case a-z and space)
# The message still might be garbage, but this is a decent
# and reasonably fast preliminary filter
valid_chars = set(c for c in string.printable[:62])
valid_chars.add(' ')
def is_valid(decode_guess):
    return (len(decode_guess) == 14 and 
            all(d in valid_chars for d in decode_guess))

# Below are the typical bit manipulation functions
# that you might find useful
# Note that ASCII_BITS is set to 7 for this problem

BITS = ('0', '1')
ASCII_BITS = 7 

def display_bits(b):
    """converts list of {0, 1}* to string"""
    return ''.join([BITS[e] for e in b])

def seq_to_bits(seq):
    return [0 if b == '0' else 1 for b in seq]

def pad_bits(bits, pad):
    """pads seq with leading 0s up to length pad"""
    assert len(bits) <= pad
    return [0] * (pad - len(bits)) + bits
        
def convert_to_bits(n):
    """converts an integer `n` to bit array"""
    result = []
    if n == 0:
        return [0]
    while n > 0:
        result = [(n % 2)] + result
        n = n / 2
    return result

def string_to_bits(s):
    def chr_to_bit(c):
        return pad_bits(convert_to_bits(ord(c)), ASCII_BITS)
    return [b for group in 
            map(chr_to_bit, s)
            for b in group]

def bits_to_char(b):
    assert len(b) == ASCII_BITS
    value = 0
    for e in b:
        value = (value * 2) + e
    return chr(value)

def list_to_string(p):
    return ''.join(p)

def bits_to_string(b):
    return ''.join([bits_to_char(b[i:i + ASCII_BITS]) 
                    for i in range(0, len(b), ASCII_BITS)])

############
# `ciphertext` is the observed message exchanged between Alice
# and Bob - which is what you need to decrypt
#
# key = convert_to_bits(mod_exp(g_b, a, p))
# ciphertext = encode(string_to_bits(plaintext), key)

ciphertext = string_to_bits(' x\x0br\x1fu/W\x00gJ@h#')

###########
# `plaintext` is the variable to set
# with the decrypted message

plaintext = "" # answer here 

# Might be a useful test function.
# If you've calculated Alice's key
# and the plaintext, you can
# calculate a cipher-text to see
# if it matches the given `ciphertext`
def test(alices_key, plaintext):
    key = convert_to_bits(mod_exp(g_b, alices_key, p))
    test_cipher = encode(string_to_bits(plaintext), key)
    return test_cipher == ciphertext

### uncomment to run
# print test(alices_key, plaintext)


#print p
binp = "{0:b}".format(p)
#print binp
#print g_a
binga = "{0:b}".format(g_a)
#print binga
#print g_b
bingb = "{0:b}".format(g_b)
#print bingb

test = g**67
#print test
#print "{0:b}".format(test)
import math

ceiling = math.log(g_a,g)
#print ceiling

#print "--------- \n\n"
candidates = []

for i in range(int(math.ceil(ceiling))):
    candidates.append(pow(g,g_b*i,p))

#print [i for i in candidates]


import math
import itertools as it

def generate_candidates(lower, upper):
    a = upper
    max_length = int(math.log(upper, 2))
    while a > lower:
        log = int(math.log(a, 2))
        ones = max_length - log
        for some_ones in it.combinations(range(log), ones):
            yield int(a + sum(2**one for one in some_ones))
        a = a / 2

# should generate every number greater than lower for which count_multiplications returns the same value as upper

def find_candidate():
    c = []
    for candidate in generate_candidates(2, 2**26):
        if pow(g, candidate, p) == g_a:
            c.append(candidate)
    return c

a = find_candidate()[0]

# key = g_b**a  ## this is too slow, use pow()

key = pow(g_b, a, p)  ## pow() handles the larger numbers better

key = convert_to_bits(mod_exp(g_b, a, p))

print bits_to_string(decode(ciphertext, key))


