from electronic_signature.signatures import ElectronicSignature
from methods_for_crypto.methods import *
import sys


def main():
    el = ElectronicSignature()
    el.start_signature_rsa()
    el.start_signature_el_gamal()
    el.start_signature_gost()

if __name__ == '__main__':
    main()
