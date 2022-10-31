import math
from random import randint


def exp_mod(a, x, p) -> int:
    b = convert_to_binary_num(x)
    y = 1
    s = a

    for i in range(0, len(b)):
        if b[i] == '1':
            y = y * s % p
        s = s * s % p
    return y


def convert_to_binary_num(x) -> list:
    binary_number = ''
    while x > 0:
        binary_number = str(x % 2) + binary_number
        x = x // 2
    binary_number = binary_number[::-1]
    return binary_number


def euclid_algorithm(a, b) -> list:
    u = [a, 1, 0]
    v = [b, 0, 1]

    while v[0] != 0:
        q = u[0] // v[0]
        t = [exp_mod(u[0], 1, v[0]), u[1] - q * v[1], u[2] - q * v[2]]
        u = v.copy()
        v = t.copy()
    return u
