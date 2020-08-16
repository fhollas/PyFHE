from FHE import FHE
from CRTPoly import CRTPoly
from numTh import findPrimes
import numpy as np
import time


def add(c1, c2, primes):
    start_time = time.time()
    modulus = 1
    for prime in primes:
        modulus *= prime
    print(modulus)
    print(c1)
    print(c2)
    result0 = (np.asarray(c1[0])) + (np.asarray(c2[0])) % modulus
    result1 = (np.asarray(c1[1])) + (np.asarray(c2[1])) % modulus
    #print(result0)
    #print(result1)
    result = []
    result.append(result0.tolist())
    result.append(result1.tolist())
    print(result)
    print("\nTime to add ciphertext:", time.time() - start_time, "seconds")
    return result

def multiply(c1, c2, primes):
    start_time = time.time()
    result = []
    fft_c10 = CRTPoly(c1[0], primes)
    fft_c11 = CRTPoly(c1[1], primes)
    fft_c20 = CRTPoly(c2[0], primes)
    fft_c21 = CRTPoly(c2[1], primes)
    fft_result0 = fft_c10 * fft_c20
    fft_result1 = fft_c10 * fft_c21 + fft_c11 * fft_c20
    fft_result2 = fft_c11 * fft_c21
    result.append(fft_result0.toPoly())
    result.append(fft_result1.toPoly())
    result.append(fft_result2.toPoly())
    print("\nTime to multiply ciphertext:", time.time() - start_time, "seconds")
    return result


def polyMul(p1, p2, primes):
    start_time = time.time()
    fft_p1 = CRTPoly(p1, primes)
    fft_p2 = CRTPoly(p2, primes)
    modulus = 1
    for prime in primes:
        modulus *= prime
    fft_result = fft_p1 * fft_p2
    result = fft_result.toPoly()
    for i, coeff in enumerate(result):
        if coeff > modulus // 2:
            result[i] -= modulus
    print("\nTime to poly multiply:", time.time() - start_time, "seconds")
    return np.remainder(result, 2).tolist()


poly_degree = 4096
stdev = 3.2
L = 4
#primes = [549755860993, 549755873281, 549755876353]
primes, bits = findPrimes(22, 4096, 4)
print(primes)
a, bits = findPrimes(10, 4096, 1)
P = a[0]
# primes = [521, 569, 577]
modulus = 1
for prime in primes:
    modulus *= prime
f = FHE(poly_degree, stdev, primes, P, L)
sk = f.secretKeyGen(64)
# sk = [[1, 0, 0, 0], [0, 1, -1, 0]]
pk = f.publicKeyGen(sk)
# pk = [[-24187115, -62847359, 2213875, 53855074], [-13973837, -16187706, -70042772, 76821192]]
switch_keys = f.switchKeyGen(sk)


#m = np.random.randint(0, 2, 100).tolist()
#m1 = np.random.randint(0, 2, 100).tolist()
m = [int(i) for i in str(bin(550304652486555850518304746550))[2:]]
m1 = [int(i) for i in str(bin(579905235455641236105943994183))[2:]]
m_mult = 550304652486555850518304746550 * 579905235455641236105943994183
m2 = [int(i) for i in str(bin(m_mult))[2:]]
m_add = 550304652486555850518304746550 + 579905235455641236105943994183
m3 = [int(i) for i in str(bin(m_add))[2:]]

print('plaintext')
print(m)
print(m1)
print(m2)
print(m3)

print('Encryption')
start_time = time.time()
c = f.homoEnc(m, pk)
print(c)
print("\nTime to encrypt:", time.time() - start_time, "seconds")

print('Decrypt m')
start_time = time.time()
dec_mm = f.homoDec(c, sk)
print(dec_mm)
print(dec_mm == m)
print("\nTime to decrypt:", time.time() - start_time, "seconds")

print('Encryption 2nd message')
start_time = time.time()
c1 = f.homoEnc(m1, pk)
print("\nTime to encrypt:", time.time() - start_time, "seconds")

print('Decrypt second message')
start_time = time.time()
dec_mm = f.homoDec(c1, sk)
print(dec_mm)
print(dec_mm == m1)
print("\nTime to decrypt:", time.time() - start_time, "seconds")

print('homo Multiply')
mul_result = multiply(c, c1, primes)
mul_result = f.keySwitch(mul_result, switch_keys[0])
mul_result = f.modSwitch(mul_result, 0)

print('Decrypt mul result')
start_time = time.time()
dec_mul_result = f.homoDec(mul_result, sk)
print("\nTime to decrypt:", time.time() - start_time, "seconds")

print('Encryption mult message')
start_time = time.time()
c2 = f.homoEnc(m2, pk)
print("\nTime to encrypt:", time.time() - start_time, "seconds")

print('Decrypt mult message')
start_time = time.time()
dec_mm = f.homoDec(c2, sk)
print(dec_mm)
print(dec_mm == m2)
print("\nTime to decrypt:", time.time() - start_time, "seconds")

#print(dec_mm == m * m1)

#print('polyMul')
#print(polyMul(m, m1, primes))
#print(dec_mul_result)
#print(dec_mul_result == polyMul(m, m1, primes))

print('homo Add')
add_result = add(c, c1, primes)
add_result = f.keySwitch(add_result, switch_keys[0])
add_result = f.modSwitch(add_result, 0)

print('Decrypt add result')
start_time = time.time()
dec_add_result = f.homoDec(add_result, sk)
print(dec_add_result)
print("\nTime to decrypt:", time.time() - start_time, "seconds")

print('Encryption add message')
start_time = time.time()
c3 = f.homoEnc(m3, pk)
print("\nTime to encrypt:", time.time() - start_time, "seconds")

print('Decrypt add message')
start_time = time.time()
dec_mm = f.homoDec(c3, sk)
print(dec_mm)
print(dec_mm == m3)
print("\nTime to decrypt:", time.time() - start_time, "seconds")

#dec_mm = f.homoDec(c, sk)
#print('Decrypt m')
# print(dec_mm)
"""
print('Modulus Switching')
c = f.modSwitch(c, 0)
c = f.modSwitch(c, 1)
"""

#new_c = ((np.asarray(c1) + np.asarray(c)) % f.modulus).tolist()
#print('Decryption')
#dec_m = f.homoDec(new_c,sk)

# if m == dec_m:
#    print('success')
# else:
#    print('fail')
#m = []
# for bit in dec_m:
#    m.append(int(bit))
# print(m)
