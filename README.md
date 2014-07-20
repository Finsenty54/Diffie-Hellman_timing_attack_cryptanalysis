<h2>Diffie-Hellman_timing_attack_cryptanalysis</h2>
==========================================

Cryptology program in Python. This is an example of how a Diffie Hellman key exchange can be vulnerable.

This side channel attack is based on the number of multiplications used in calculating the key (timing attack).

<hr>

Some example values are used here for the generator (g), prime (p), and encryptions (g^a mod p, g^b mod p).

The number of multiplications (n) is given.  In the wild, n would be estimated by timing each communication.  
During periods of rapid communications between points, the pool of values to determine n can increase.

Timing attack resistant systems employ methods to obscure information about decryption times for calculation of messages.

<hr>

For the purposes of this example, all of the public information of a Diffie-Hellman key exchange was intercepted over an open channel including the number of multiplications `n` needed to calculate `(g**b)**a mod p`
where `a` is Alice's private key and `b` is Bob's private key.
This information should be enough to determine Alice's private key and then decrypt the message.  The Python methods referred to here are available for review on the relevant Github. 

The method `count_multiplications()` can be used to match a combination against the value of n, in order to slim down the possible combinations.  However, an interesting point here is that simply knowing the value of `n` could lead to a break, even without weeding out irrelevant values.  While this sounds inefficient for cryptanalysis purposes (and of course it is inefficient), it shows how dangerous the timing attack can be at small values, for example where `g^a%p` is roughly 100 bits (or less) as in this case.  Therefore, the method `find_candidate()` is included to illustrate this point.

<hr>

The example values allow for successful cryptanalysis within a practical number of iterations as shown here:

`mint-vm-mate@mintvmmate-VirtualBox ~/Desktop/crypto $ python dh.timing.attack.1.py`

`attack at dawn `

`g_a  1110011001101010110001001100011000001011010101010101101010000100001110011111001010111101100011100`

`len(g_a)  97 `

`g_b  111101100100011000000101001011111100110101101011001010111000000011110000100101000100111001001100111`

`len(g_b)  99 `

`p  1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111101100111`
`len(p)  100 `

`key  11000000010100001000000`

`len(key)  23 `

`number of iterations to recover key  196418`

`mint-vm-mate@mintvmmate-VirtualBox ~/Desktop/crypto $ `


