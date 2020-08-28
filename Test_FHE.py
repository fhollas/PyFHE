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
    result0 = (np.asarray(c1[0])) + (np.asarray(c2[0])) % modulus
    result1 = (np.asarray(c1[1])) + (np.asarray(c2[1])) % modulus
    result = []
    result.append(result0.tolist())
    result.append(result1.tolist())
    #print(result)
    print("Time to add ciphertext:", time.time() - start_time, "seconds")
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
    print("Time to multiply ciphertext:", time.time() - start_time, "seconds")
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
    print("Time to poly multiply:", time.time() - start_time, "seconds")
    return np.remainder(result, 2).tolist()


poly_degree = 512
stdev = 3.2
L = 4
primes, bits = findPrimes(22, 512, 4)
print(primes)
a, bits = findPrimes(10, 512, 1)
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

m = [int(i) for i in str(bin(550304652486555850518304746550))[2:]]
m1 = [int(i) for i in str(bin(579905235455641236105943994183))[2:]]
m_mult = 550304652486555850518304746550 * 579905235455641236105943994183
m2 = [int(i) for i in str(bin(m_mult))[2:]]
m_add = 550304652486555850518304746550 + 579905235455641236105943994183
m3 = [int(i) for i in str(bin(m_add))[2:]]

print("Message 1:", m)
print("Message 2:", m1)
print("multiplied Messages:", m2)
print("added Messages:", m3)

print('\n==Encrypt 1st message')
start_time = time.time()
c = f.homoEnc(m, pk)
#print(c)
print("Time to encrypt:", time.time() - start_time, "seconds")

print('\n==Decrypt 1st message')
start_time = time.time()
dec_mm = f.homoDec(c, sk)
#print(dec_mm)
print(dec_mm == m)
print("Time to decrypt:", time.time() - start_time, "seconds")

print('\n==Encrypt 2nd message')
start_time = time.time()
c1 = f.homoEnc(m1, pk)
#print(c1)
print("Time to encrypt:", time.time() - start_time, "seconds")

print('\n==Decrypt second message')
start_time = time.time()
dec_mm = f.homoDec(c1, sk)
#print(dec_mm)
print(dec_mm == m1)
print("Time to decrypt:", time.time() - start_time, "seconds")

print('\n==Homomorphic Multiplication')
mul_result = multiply(c, c1, primes)
mul_result = f.keySwitch(mul_result, switch_keys[0])
mul_result = f.modSwitch(mul_result, 0)

print('\n==Decrypt multiplied ciphers')
start_time = time.time()
dec_mul_result = f.homoDec(mul_result, sk)
#print(dec_mul_result)
print("Time to decrypt:", time.time() - start_time, "seconds")

print('\n==Encryption multiplied plaintexts')
start_time = time.time()
c2 = f.homoEnc(m2, pk)
print("Time to encrypt:", time.time() - start_time, "seconds")

print('\n==Decrypt multiplied plaintexts')
start_time = time.time()
dec_mm = f.homoDec(c2, sk)
#print(dec_mm)
print("Time to decrypt:", time.time() - start_time, "seconds")
print(f"Homomorphic multiplication succesful: {dec_mm == m2}")

#print(dec_mm == m * m1)

#print('polyMul')
#print(polyMul(m, m1, primes))
#print(dec_mul_result)
#print(dec_mul_result == polyMul(m, m1, primes))

print('\n==Homomorphic Addition')
add_result = add(c, c1, primes)
#print(add_result)

print('\n==Decrypt added ciphers')
start_time = time.time()
dec_add_result = f.homoDec(add_result, sk)
#print(dec_add_result)
print("Time to decrypt:", time.time() - start_time, "seconds")

print('\n==Encrypt added plaintexts')
start_time = time.time()
c3 = f.homoEnc(m3, pk)
print("Time to encrypt:", time.time() - start_time, "seconds")

print('\n==Decrypt added plaintexts')
start_time = time.time()
dec_mm = f.homoDec(c3, sk)
#print(dec_mm)
print("Time to decrypt:", time.time() - start_time, "seconds")
print(f"Homomorphic addition succesful: {dec_mm == m3}")
