import unittest
import datetime
import matplotlib
from matplotlib import pyplot
from generator import *
from rsacrypt import *
import math

def timing_test():
    bitsize_list = (2**i for i in range(5,11))
    timings = {}
    for i in bitsize_list:
        g = RSAKeyPairGenerator()
        res = None
        start = datetime.datetime.now()
        res = g.get_prime_number(bitsize=i)
        end = datetime.datetime.now()
        if res:
            timings.update({i: (end-start)})
    return timings

class PrimesTest(unittest.TestCase):

    def test_is_prime(self):
        g = RSAKeyPairGenerator()
        self.assertTrue(g.is_prime(456435634634563456342431463643793745897395829))
        self.assertTrue(g.is_prime(456435634634563456342431463643793745897395719365245645646545737))
        self.assertFalse(g.is_prime(345834564378658736458364785637846578364856378456873658374563784))
        self.assertFalse(g.is_prime(824628648236492648299987432938742297974924926492648276487648236))

    def test_xgcd(self):
        g = RSAKeyPairGenerator()
        self.assertEqual(g.xgcd(234234234, 2342), math.gcd(234234234,2342))

if __name__ == '__main__':
    unittest.main()
