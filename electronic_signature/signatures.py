import hashlib
from random import randint, randrange
from methods_for_crypto.methods import *
from sympy import isprime, randprime
import sys


class ElectronicSignature:
    def __signature_rsa(self, m, c, n, p) -> int:
        hash = int(hashlib.sha256(m.encode()).hexdigest(), 16) % p + 1
        s = exp_mod(hash, c, n)
        return s

    def __check_signature_rsa(self, m, s, d, n, p) -> bool:
        hash = int(hashlib.sha256(m.encode()).hexdigest(), 16) % p + 1
        if hash == exp_mod(s, d, n):
            return True
        return False

    def start_signature_rsa(self) -> None:
        p = 0
        q = 0
        while not isprime(p) and not isprime(q):
            p = randprime(0, math.pow(10, 10))
            q = randprime(0, math.pow(10, 10))

        n = p * q
        f = (p - 1) * (q - 1)

        d = 0
        while math.gcd(d, f) != 1:
            d = randint(1, f)

        c = euclid_algorithm(d, f)[1]
        if c < 0:
            c += f

        file = open('./resources/data.txt', mode='r')
        m = file.read()
        file.close()

        s = self.__signature_rsa(m, c, n, p)

        file = open('./resources/data_rsa.txt', mode='w')
        file.write(m + '\n' + str(s))
        file.close()

        file = open('./resources/data_rsa.txt', mode='r')
        file.close()

        if self.__check_signature_rsa(m, s, d, n, p) is True:
            print('Подпись RSA подтверждена')
        else:
            print(f'Подпись RSA некорректна')

    def __signature_el_gamal(self, m, p, g) -> int:
        x = randint(2, p - 1)
        y = exp_mod(g, x, p)

        hash = int(hashlib.sha256(m.encode()).hexdigest(), 16) % p + 2

        k = 0
        while True:
            k = randprime(1, p - 1)
            if math.gcd(k, p - 1):
                break

        r = exp_mod(g, k, p)

        u = (hash - x * r) % (p - 1)
        s = (euclid_algorithm(k, p - 1)[1] * u) % (p - 1)

        return r, s, y

    def __check_signature_el_gamal(self, m, p, g, r, s, y) -> bool:
        hash = int(hashlib.sha256(m.encode()).hexdigest(), 16) % p + 2

        value = (exp_mod(y, r, p) * exp_mod(r, s, p)) % p

        if exp_mod(g, hash, p) == value:
            return True
        return False

    def start_signature_el_gamal(self) -> None:
        file = open('./resources/data.txt', mode='r')
        m = file.read()
        file.close()
        p = 0
        g = 0
        while True:
            q = randprime(0, int(math.pow(10, 10)))
            p = 2 * q + 1
            g = randint(1, p - 1)
            if isprime(p):
                if 1 < g < p - 1 and exp_mod(g, q, p) != 1:
                    break
        r, s, y = self.__signature_el_gamal(m, p, g)
        file = open('./resources/data_el_gamal.txt', mode='w')
        file.write(m + '\n' + str(r) + ' ' + str(s))
        file.close()

        file = open('./resources/data_el_gamal.txt', mode='r')
        last_line = file.readlines()[-1].split()
        file.close()
        if self.__check_signature_el_gamal(m, p, g, int(last_line[0]), int(last_line[1]), y) is True:
            print('Подпись Эль-Гамаля подтверждена')
        else:
            print(f'Подпись Эль-Гамаля некорректна')

    def __signature_gost(self, m, a, q, p, x) -> list:
        hash = int(hashlib.sha256(m.encode()).hexdigest(), 16) % q
        if hash == 0:
            hash += 1
        k = randint(1, q)
        r = 0
        s = 0
        while True:
            k = randrange(1, q)
            r = exp_mod(a, k, p) % q
            if r == 0:
                continue
            s = (k * hash + x * r) % q
            if s != 0:
                break
        return r, s

    def __check_signature_gost(self, m, r, s, q, p, a, y) -> bool:
        h = int(hashlib.sha256(m.encode()).hexdigest(), 16) % q
        if h == 0:
            h += 1
        assert 0 < r < q
        assert 0 < s < q
        u1 = s * euclid_algorithm(h, q)[1] % q
        u2 = -r * euclid_algorithm(h, q)[1] % q
        u = exp_mod(a, u1, p) * exp_mod(y, u2, p) % p % q
        if u == r:
            return True
        return False

    def start_signature_gost(self) -> None:
        q = randprime(1 << 15, (1 << 16) - 1)
        while True:
            b = randint((1 << 30) // q, ((1 << 31) - 1) // q)
            if isprime(p := b * q + 1):
                break

        while True:
            g = randrange(2, p - 1)
            if (a := exp_mod(g, b, p)) > 1:
                break

        x = randint(1, q)
        y = exp_mod(a, x, p)

        file = open('./resources/data.txt', mode='r')
        m = file.read()
        file.close()

        r, s = self.__signature_gost(m, a, q, p, x)

        file = open('./resources/data_gost.txt', mode='w')
        file.write(m + '\n' + str(r) + ' ' + str(s))
        file.close()

        file = open('./resources/data_gost.txt', mode='r')
        file.readlines()[-1].split()
        file.close()

        if self.__check_signature_gost(m, r, s, q, p, a, y) is True:
            print(f'Подпись ГОСТ подтверждена')
        else:
            print(f'Подпись ГОСТ некорректна')