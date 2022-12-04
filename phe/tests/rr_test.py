#!/usr/bin/env python
# Portions Copyright 2012 Google Inc. All Rights Reserved.
# This file has been modified by NICTA
import phe.encoding
from phe.paillier import PaillierPrivateKey, PaillierPublicKey

# This file is part of pyphe.
#
# Pyphe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Pyphe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pyphe.  If not, see <http://www.gnu.org/licenses/>.

"""Unittest for paillier module."""

import logging
import unittest
import sys
import math

from phe import paillier

class PaillerRandomnesRecovery(unittest.TestCase):

    def testRRAttributes(self):
        _, private_key = paillier.generate_paillier_keypair()
        self.assertTrue(hasattr(private_key, 'l'))
        self.assertTrue(hasattr(private_key, 'mu'))
        self.assertTrue(hasattr(private_key, 'x'))

    def testRR(self):
        public_key, private_key = paillier.generate_paillier_keypair()
        data = 4
        encrypted_message =  public_key.encrypt(data)
        decrypted_message, randomness = private_key.decommitment_decrypt(encrypted_message)
        result =  public_key.verify(encrypted_message, decrypted_message, randomness)
        self.assertTrue(result)