"""
Author:
   Justin Cappos

This code is based loosely on an earlier implementation by Sebastien
Martini (seb@dbzteam.org) listed as tss on github.   I take
responsibility for all bugs and remaining code.

Start Date: 11 March 2013

Purpose:
  This is a version of Shamir's secret sharing that is:

  1) built expressly to have the APIs I need

  2) definitely not performance tuned. (It's geared for readability.)

  This is just a proof-of-concept!!!

  To be used as a library for a project I'm calling PolyPasswordHasher.


Example:
  import shamirsecret
  # create a new object with some secret...
  mysecret = shamirsecret.ShamirSecret(2, 'my shared secret')
  # get shares out of it...

  a = mysecret.compute_share(4)
  b = mysecret.compute_share(6)
  c = mysecret.compute_share(1)
  d = mysecret.compute_share(2)

  # Recover the secret value
  newsecret = shamirsecret.ShamirSecret(2)

  newsecret.recover_secretdata([a,b,c])  # note, two would do...

  # d should be okay...
  assert(newsecret.is_valid_share(d))

  # change a byte
  d[1][3] = d[1][3] - 1

  # but not now...
  assert(newsecret.is_valid_share(d) is False)

Notes:
 - This module *intentionally* does not do hashing to detect incorrect
   shares.  For my application, I want them to get an (undetected) incorrect
   decoding if a share is wrong.
"""
import os

__author__ = 'Justin Cappos (jcappos@poly.edu)'
__version__ = '0.1'
__license__ = 'MIT'
__all__ = ['ShamirSecret']







class ShamirSecret(object):
  """
    This performs Shamir Secret Sharing operations in an incremental way
    that is useful for PolyPasswordHasher.  It allows checking membership, generating
    shares one at a time, etc.
  """

  def __init__(self, threshold, secretdata=None):
    """Creates an object.   One must provide the threshold.   If you want
       to have it create the coefficients, etc. call it with secret data"""
    self.threshold=threshold
    self.secretdata=secretdata

    self._coefficients = None

    # if we're given data, let's compute the random coefficients.   I do this
    # here so I can later iteratively compute the shares
    if secretdata is not None:

      self._coefficients = []
      for secretbyte in secretdata:
        # this is the polynomial.   The first byte is the secretdata.
        # The next threshold-1 are (crypto) random coefficients
        # I'm applying Shamir's secret sharing separately on each byte.
        thesecoefficients = bytearray(secretbyte+os.urandom(threshold-1))

        self._coefficients.append(thesecoefficients)



  def is_valid_share(self, share):
    """ This validates that a share is correct given the secret data.
        It returns True if it is valid, False if it is not, and raises
        various errors when given bad data.
        """

    # the share is of the format x, f(x)f(x)
    if type(share) is not tuple:
      raise TypeError("Share is of incorrect type: "+str(type(share)))

    if len(share) !=2:
      raise ValueError("Share is of incorrect length: "+str(share))


    if self._coefficients is None:
      raise ValueError("Must initialize coefficients before checking is_valid_share")

    if len(self._coefficients) != len(share[1]):
      raise ValueError("Must initialize coefficients before checking is_valid_share")

    x, fx = share

    # let's just compute the right value
    correctshare = self.compute_share(x)

    if correctshare == share:
      return True
    else:
      return False





  def compute_share(self, x):
    """ This computes a share, given x.   It returns a tuple with x and the
        individual f(x_0)f(x_1)f(x_2)... bytes for each byte of the secret.
        This raises various errors when given bad data.
        """

    if type(x) is not int:
      raise TypeError("In compute_share, x is of incorrect type: "+str(type(x)))

    if x<=0 or x>=256:
      raise ValueError("In compute_share, x must be between 1 and 255, not: "+str(x))

    if self._coefficients is None:
      raise ValueError("Must initialize coefficients before computing a share")

    sharebytes = bytearray()
    # go through the coefficients and compute f(x) for each value.
    # Append that byte to the share
    for thiscoefficient in self._coefficients:
      thisshare = _f(x,thiscoefficient)
      sharebytes.append(thisshare)

    return (x,sharebytes)





  def recover_secretdata(self, shares):
    """ This recovers the secret data and coefficients given at least threshold
        shares.   Note, if any provided share does not decode, an error is
        raised."""

    # discard duplicate shares
    newshares = []
    for share in shares:
      if share not in newshares:
        newshares.append(share)
    shares = newshares


    if self.threshold > len(shares):
      raise ValueError("Threshold:"+str(self.threshold)+" is smaller than the number of unique shares:"+str(len(shares))+".")

    if self.secretdata is not None:
      raise ValueError("Recovering secretdata when some is stored.   Use check_share instead.")

    # the first byte of each share is the 'x'.
    xs = []
    for share in shares:
      # the first byte should be unique...
      if share[0] in xs:
        raise ValueError("Different shares with the same first byte! '"+str(share[0])+"'")
      # ...and all should be the same length
      if len(share[1])!=len(shares[0][1]):
        raise ValueError("Shares have different lengths!")

      xs.append(share[0])


    mycoefficients = []
    mysecretdata = ''

    # now walk through each byte of the secret and do lagrange interpolation
    # to compute the coefficient...
    for byte_to_use in range(0,len(shares[0][1])):

      # we need to get the f(x)s from the appropriate bytes
      fxs = []
      for share in shares:
        fxs.append(share[1][byte_to_use])

      # build this polynomial
      resulting_poly = _full_lagrange(xs,fxs)


      # If I have more shares than the threshold, the higher order coefficients
      # (those greater than threshold) must be zero (by Lagrange)...
      if resulting_poly[:self.threshold] + [0]*(len(shares)-self.threshold) != resulting_poly:
        raise ValueError("Shares do not match.   Cannot decode")

      # track this byte...
      mycoefficients.append(bytearray(resulting_poly))

      mysecretdata += chr(resulting_poly[0])



    # they check out!   Assign to the real ones!
    self._coefficients = mycoefficients

    self.secretdata = mysecretdata





####################### END OF MAIN CLASS #######################






### Private math helpers... Lagrange interpolation, polynomial math, etc.



# This actually computes f(x).  It's private and not needed elsewhere...
def _f(x, coefs_bytes):
  """ This computes f(x) = a + bx + cx^2 + ...
      The value x is x in the above formula.
      The a, b, c, etc. bytes are the coefs_bytes in increasing order.
      It returns the result."""
  if x == 0:
    raise ValueError('invalid share index value, cannot be 0')
  accumulator = 0

  # start with x_i = 1.   We'll multiply by x each time around to increase it.
  x_i = 1
  for c in coefs_bytes:
    # we multiply this byte (a,b, or c) with x raised to the right power.
    accumulator = _gf256_add(accumulator, _gf256_mul(c, x_i))
    # raise x_i to the next power by multiplying by x.
    x_i = _gf256_mul(x_i, x)

  return accumulator





# unfortunately, numpy doesn't seem to do polynomial arithematic over
# finite fields...   :(
#
# This helper function takes two lists and 'multiplies' them.   I only tested
# the second list is of size <=2, but I don't think this matters.
#
# for example: [1,3,4] * [4,5] will compute (1 + 3x + 4x^2) * (4 - 5x) ->
# 4 + 17x + 31x^2 + 20x^3    or [4, 17, 31, 20]
# or at least, this would be the case if we weren't in GF256...
# in GF256, this is:
# 4 + 9x + 31x^2 + 20x^3    or [4, 9, 31, 20]
def _multiply_polynomials(a,b):

  # I'll compute each term separately and add them together
  resultterms = []

  # this grows to account for the fact the terms increase as it goes
  # for example, multiplying by x, shifts all 1 right
  termpadding = []
  for bterm in b:
    thisvalue = termpadding[:]
    # multiply each a by the b term.
    for aterm in a:
      thisvalue.append(_gf256_mul(aterm,bterm))
#      thisvalue.append(aterm * bterm)

    resultterms = _add_polynomials(resultterms,thisvalue)
    # moved another x value over...
    termpadding.append(0)

  return resultterms




# adds two polynomials together...
def _add_polynomials(a,b):

  # make them the same length...
  if len(a) < len(b):
    a = a + [0]*(len(b)-len(a))
  if len(a) > len(b):
    b = b + [0]*(len(a)-len(b))

  assert(len(a)==len(b))

  result = []
  for pos in range(len(a)):
#    result.append(a[pos] + b[pos])
    result.append(_gf256_add(a[pos],b[pos]))

  return result



# For lists containing xs and fxs, compute the full Lagrange basis polynomials.
# We want it all to populate the coefficients to check the shares by new
# share generation
def _full_lagrange(xs, fxs):
  assert(len(xs) == len(fxs))

  returnedcoefficients = []
  # we need to compute:
  # l_0 =  (x - x_1) / (x_0 - x_1)   *   (x - x_2) / (x_0 - x_2) * ...
  # l_1 =  (x - x_0) / (x_1 - x_0)   *   (x - x_2) / (x_1 - x_2) * ...
  for i in range(len(fxs)):

    this_polynomial = [1]
    # take the terms one at a time.
    # I'm computing the denominator and using it to compute the polynomial.
    for j in range(len(fxs)):
      # skip the i = jth term because that's how Lagrange works...
      if i == j:
        continue

      # I'm computing the denominator and using it to compute the polynomial.
      denominator = _gf256_sub(xs[i],xs[j])
#      denominator = xs[i]-xs[j]

      # don't need to negate because -x = x in GF256
      this_term = [_gf256_div(xs[j],denominator), _gf256_div(1,denominator)]
#      this_term = [-xs[j]/denominator, 1/denominator]

      # let's build the polynomial...
      this_polynomial = _multiply_polynomials(this_polynomial,this_term)

    # okay, now I've gone and computed the polynomial.   I need to multiply it
    # by the result of f(x)

    this_polynomial = _multiply_polynomials(this_polynomial, [fxs[i]])

    # we've solved this polynomial.   We should add to the others.
    returnedcoefficients = _add_polynomials(returnedcoefficients, this_polynomial)

  return returnedcoefficients






###### GF256 helper functions...   ###########

# GF(256) lookup tables using x^8 + x^4 + x^3 + x + 1
# FYI: addition is just XOR in this field.
# I used this because it's used in tss and AES

_GF256_EXP = [0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff,
       0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
       0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4,
       0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
       0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26,
       0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
       0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
       0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
       0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7,
       0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
       0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
       0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
       0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0,
       0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
       0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec,
       0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
       0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2,
       0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
       0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0,
       0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
       0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
       0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
       0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf,
       0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
       0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09,
       0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
       0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91,
       0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
       0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c,
       0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
       0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd,
       0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01]
# The last entry was wrong!!!   I've fixed it.

# entry 0 is undefined
_GF256_LOG = [ 0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6,
        0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
        0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef,
        0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
        0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a,
        0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
        0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24,
        0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
        0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94,
        0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
        0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62,
        0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
        0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42,
        0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
        0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca,
        0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
        0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74,
        0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
        0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5,
        0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
        0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec,
        0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
        0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86,
        0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
        0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc,
        0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
        0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47,
        0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
        0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89,
        0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
        0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18,
        0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07]


def _gf256_add(a, b):
  return a ^ b

def _gf256_sub(a, b):
  return _gf256_add(a, b)

def _gf256_mul(a, b):
  if a == 0 or b == 0:
    return 0
  return _GF256_EXP[(_GF256_LOG[a] + _GF256_LOG[b]) % 255]

def _gf256_div(a, b):
  if a == 0:
    return 0
  if b == 0:
    raise ZeroDivisionError
  return _GF256_EXP[(_GF256_LOG[a] - _GF256_LOG[b]) % 255]

