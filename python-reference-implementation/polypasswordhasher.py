"""
<Author>
  Justin Cappos

<Start Date>
  March 14th, 2013

<Description>
  A basic library that demonstrates PolyHash when applied to passwords (see
  https://polypasswordhasher.poly.edu/ for details).   This includes shielded
  password support via AES 256.

<Usage>
  import polypasswordhasher

  # require knowledge of 10 shares to decode others.   Create a blank, new
  # password file...
  pph = polypasswordhasher.PolyPasswordHasher(threshold = 10, passwordfile = None)

  # create three admins so that any two have the appropriate threshold
  pph.create_account('admin','correct horse',5)
  pph.create_account('root','battery staple',5)
  pph.create_account('superuser','purple monkey dishwasher',5)

  # make some normal user accounts...
  pph.create_account('alice','kitten',1)
  pph.create_account('bob','puppy',1)
  pph.create_account('charlie','velociraptor',1)
  pph.create_account('dennis','menace',0)
  pph.create_account('eve','iamevil',0)

  # try some logins and make sure we see what we expect...
  assert(pph.is_valid_login('alice','kitten') == True)
  assert(pph.is_valid_login('admin','correct horse') == True)
  assert(pph.is_valid_login('alice','nyancat!') == False)
  assert(pph.is_valid_login('dennis','menace') == True)
  assert(pph.is_valid_login('dennis','password') == False)

  # persist the password file to disk
  pph.write_password_data('securepasswords')

  # If I remove this from memory, I can't use the data on disk to check
  # passwords without a threshold
  pph = None

  # let's load it back in
  pph = polypasswordhasher.PolyPasswordHasher(threshold = 10,passwordfile = 'securepasswords')

  # The password information is essentially useless alone.   You cannot know
  # if a password is valid without threshold or more other passwords!!!
  try:
    pph.is_valid_login('alice','kitten')
  except ValueError:
    pass
  else:
    print "Can't get here!   It's still bootstrapping!!!"

  # with a threshold (or more) of correct passwords, it decodes and is usable.
  pph.unlock_password_data([('admin','correct horse'), ('root','battery staple'), ('bob','puppy'),('dennis','menace'])

  # now, I can do the usual operations with it...
  assert(pph.is_valid_login('alice','kitten') == True)

  pph.create_account('moe','tadpole',1)
  pph.create_account('larry','fish',0)
  ...


"""

__author__ = 'Justin Cappos (jcappos@poly.edu)'
__version__ = '0.1'
__license__ = 'MIT'
__all__ = ['PolyPasswordHasher']


from hashlib import sha256

# For shielded password support...
from Crypto.Cipher import AES

import fastshamirsecret as shamirsecret
#import shamirsecret

import os

import pickle


# This is a PolyHash object that has special routines for passwords...
class PolyPasswordHasher(object):

  # this is keyed by user name.  Each value is a list of dicts (really a
  # struct) where each dict contains the salt, sharenumber, and
  # passhash (saltedhash XOR shamirsecretshare).
  accountdict = None
  bootstrap_accounts = None

  # This contains the shamirsecret object for this data store
  shamirsecretobj = None

  # Is the secret value known?   In other words, is it safe to use the
  # passwordfile
  knownsecret = False

  # length of the salt in bytes
  saltsize = 16

  # ICB iterations and recombination iterations...
  icb_iterations = 1000
  recombination_iterations = 100000

  # secret verification routines
  secret_length = 32
  secret_integrity_check = None

  # number of bytes of data used for isolated validation...
  isolated_check_bits= 0

  # shielded support.   This could be random (and unknown) in the default
  # algorithm
  shieldedkey = None

  # number of used shares.   While I could duplicate shares for normal users,
  # I don't do so in this implementation.   This duplication would allow
  # co-analysis of password hashes
  nextavailableshare = None

  def __init__(self, threshold, passwordfile = None, isolated_check_bits = 0):
    """Initialize a new (empty) object with the threshold.   I could store
       the threshold in the file, but don't do this currently.   I just assume
       it's known to the program"""

    self.threshold = threshold

    self.accountdict = {}
    self.bootstrap_accounts = []

    self.isolated_check_bits = isolated_check_bits

    # creating a new password file
    if passwordfile is None:
      # generate a 256 bit key for AES.   I need 256 bits anyways
      # since I'll be XORing by the
      # output of SHA256, I want it to be 256 bits (or 32 bytes) long
      # we add an integrity check at the end of the secret
      self.shieldedkey = self.create_secret()

      # protect this key.
      self.shamirsecretobj = shamirsecret.ShamirSecret(threshold, self.shieldedkey)
      # I've generated it now, so it is safe to use!
      self.knownsecret = True
      self.nextavailableshare = 1

      # create the integrity check
      self.secret_integrity_check = self.create_integrity_check(self.shieldedkey)

      return

    # Okay, they have asked me to load in a password file!
    self.shamirsecretobj = shamirsecret.ShamirSecret(threshold)
    self.knownsecret = False
    self.shieldedkey = None

    # A real implementation would need much better error handling
    passwordfiledata = pickle.load(open(passwordfile))

    # just want to deserialize this data.  Should do better validation
    self.accountdict = passwordfiledata.accountdict
    self.secret_integrity_check = passwordfiledata.secret_integrity_check

    assert(type(self.accountdict) is dict)

    # compute which share number is the largest used...
    for username in self.accountdict:
      # look at each share
      for share in self.accountdict[username]:
        self.nextavailableshare = max(self.nextavailableshare, share['sharenumber'])

    # ...then use the one after when I need a new one.
    self.nextavailableshare += self.nextavailableshare






  def create_account(self, username, password, shares):
    """Create a new account.  Raises a ValueError if given bad data or if the
       system isn't initialized"""



    if username in self.accountdict:
      raise ValueError("Username exists already!")

    # Were I to add support for changing passwords, etc. this code would be
    # moved to an internal helper.

    if shares>255 or shares<0:
      raise ValueError("Invalid number of shares: "+str(shares)+".")

    # Note this is just an implementation limitation.   I could do all sorts
    # of things to get around this (like just use a bigger field).
    if shares + self.nextavailableshare > 255:
      raise ValueError("Would exceed maximum number of shares: "+str(shares)+".")

    # for each share, we will add the appropriate dictionary.
    self.accountdict[username] = []

    # we are bootstrapping, we will create a bootstrap account
    if not self.knownsecret:

      # We can only create shielded accounts while bootstrapping
      if shares != 0:
        del self.accountdict[username]
        raise ValueError("Cannot produce shares, still bootstrapping!")
      else:
        thisentry = {}
        thisentry['sharenumber'] = -1
        thisentry['salt'] = os.urandom(self.saltsize)
        saltedpasswordhash = sha256(thisentry['salt'] + password).digest()
        thisentry['passhash'] = saltedpasswordhash
        self.accountdict[username].append(thisentry)

        # we will use this to update accounts one bootstrap accounts are finished
        self.bootstrap_accounts.append(thisentry)


    elif shares == 0:

      thisentry = {}
      thisentry['sharenumber'] = 0

      # get a random salt, salt the password and store the salted hash
      thisentry['salt'] = os.urandom(self.saltsize)
      saltedpasswordhash = sha256(thisentry['salt']+password).digest()

      # Encrypt the salted secure hash.   The salt should make all entries
      # unique when encrypted.
      thisentry['passhash'] = AES.new(self.shieldedkey).encrypt(saltedpasswordhash)

      # technically, I'm supposed to remove some of the prefix here, but why
      # bother?

      # append the isolated validation data...
      thisentry['passhash'] += self.create_isolated_validation_bits(saltedpasswordhash)

      self.accountdict[username].append(thisentry)
      # and exit (don't increment the share count!)

      return

    for sharenumber in range(self.nextavailableshare, self.nextavailableshare+shares):
      thisentry = {}
      thisentry['sharenumber'] = sharenumber
      # take the bytearray part of this
      shamirsecretdata = self.shamirsecretobj.compute_share(sharenumber)[1]
      thisentry['salt'] = os.urandom(self.saltsize)
      saltedpasswordhash = sha256(thisentry['salt']+password).digest()
      # XOR the two and keep this.   This effectively hides the hash unless
      # protector hashes can be simultaneously decoded
      thisentry['passhash'] = _do_bytearray_XOR(saltedpasswordhash, shamirsecretdata)
      # append the isolated validation data...
      thisentry['passhash'] += self.create_isolated_validation_bits(saltedpasswordhash)


      self.accountdict[username].append(thisentry)

    # increment the share counter.
    self.nextavailableshare += shares




  def is_valid_login(self,username,password):
    """ Check to see if a login is valid."""

    if not self.knownsecret and self.isolated_check_bits == 0:
      raise ValueError("Still bootstrapping and isolated validation is disabled!")


    if username not in self.accountdict:
      raise ValueError("Unknown user '"+username+"'")

    # I'll check every share.   I probably could just check the first in almost
    # every case, but this shouldn't be a problem since only admins have
    # multiple shares.   Since these accounts are the most valuable (for what
    # they can access in the overall system), let's be thorough.

    for entry in self.accountdict[username]:

      saltedpasswordhash = sha256(entry['salt']+password).digest()

      # if this is a bootstrap account...
      if entry['sharenumber'] == -1:
          return saltedpasswordhash == entry['passhash']

      # If bootstrapping, isolated validation needs to be done here!
      if not self.knownsecret:
#        if saltedpasswordhash[len(saltedpasswordhash)-self.isolated_check_bits:] == entry['passhash'][len(entry['passhash'])-self.isolated_check_bits:]:
        if self.isolated_validation(saltedpasswordhash, entry['passhash']):
          return True
        else:
          return False

      # XOR to remove the salted hash from the password
      sharedata = _do_bytearray_XOR(saltedpasswordhash, entry['passhash'][:len(entry['passhash'])-self.isolated_check_bits])

      if self.isolated_check_bits > 0:
        isolated_check = self.isolated_validation(saltedpasswordhash, entry['passhash'])
      else:
        isolated_check = False

      # If a shielded account...
      if entry['sharenumber'] == 0:
        # return true if the password encrypts the same way...
        if AES.new(self.shieldedkey).encrypt(saltedpasswordhash) == entry['passhash'][:len(entry['passhash'])-self.isolated_check_bits]:
          return True

        # or false otherwise
        if isolated_check:
            print("Isolated check matches but full hash doesn't, this might be a break-in!")
        return False


      # now we should have a shamir share (if all is well.)
      share = (entry['sharenumber'],sharedata)

      # If a normal share, return T/F depending on if this share is valid.
      if self.shamirsecretobj.is_valid_share(share):
          return True

      if isolated_check:
          print("Isolated check matches but full hash doesn't, this might be a break-in!")

      return False



  def write_password_data(self, passwordfile):
    """ Persist the password data to disk."""
    if self.threshold >= self.nextavailableshare:
      raise ValueError("Would write undecodable password file.   Must have more shares before writing.")

    # Need more error checking in a real implementation
    # we will backup important information, set it to None and write the rest
    secret_backup = self.knownsecret
    shieldedkey_backup = self.shieldedkey
    shamirsecretobj_backup = self.shamirsecretobj

    self.secret = None
    self.shieldedkey = None
    self.shamirsecretobj = None

    open(passwordfile,'w').write(pickle.dumps(self))

    self.knownsecret = secret_backup
    self.shieldedkey = shieldedkey_backup
    self.shamirsecretobj = shamirsecretobj_backup


  def unlock_password_data(self, logindata):
    """Pass this a list of username, password tuples like: [('admin',
       'correct horse'), ('root','battery staple'), ('bob','puppy')]) and
       it will use this to access the password file if possible."""



    if self.knownsecret:
      raise ValueError("PPH is already in normal operation!")


    # Okay, I need to find the shares first and then see if I can recover the
    # secret using this.

    sharelist = []

    for (username, password) in logindata:
      if username not in self.accountdict:
        raise ValueError("Unknown user '"+username+"'")

      for entry in self.accountdict[username]:

        # ignore shielded account entries...
        if entry['sharenumber'] == 0:
          continue

        thissaltedpasswordhash = sha256(entry['salt']+password).digest()
        thisshare = (entry['sharenumber'],
            _do_bytearray_XOR(thissaltedpasswordhash,
                entry['passhash'][:len(entry['passhash'])-self.isolated_check_bits]))


        sharelist.append(thisshare)
    # This will raise a ValueError if a share is incorrect or there are other
    # issues (like not enough shares).
    self.shamirsecretobj.recover_secretdata(sharelist)
    if not self.verify_secret(self.shamirsecretobj.secretdata):
        raise ValueError("This is not a valid secret recombination, wrong account information provided")

    self.shieldedkey = self.shamirsecretobj.secretdata

    # update bootstrap accounts to shielded accounts
    for entry in self.bootstrap_accounts:
        entry['passshash'] = AES.new(self.shieldedkey).encrypt(entry['passhash'])
        entry['sharenumber'] = 0

    # we shouldn't have any bootstrap accounts now
    self.bootstrap_accounts = []


    # it worked!
    self.knownsecret = True

  def isolated_validation(self, passhash, stored_hash):
    """
    Compare local icb's with the provided icb to see if the provided
    password is correct
    """
    passhash_icb = self.create_isolated_validation_bits(passhash)
    local_icb = stored_hash[len(stored_hash) - self.isolated_check_bits:]
    return passhash_icb == local_icb

  def verify_secret(self, secret):
    """
    Checks whether the secret matches the stored integrity check

    the boolean returned indicates whether it falls under the
    fingerprint or not
    """
    secret_digest = self.create_integrity_check(secret)

    return secret_digest == self.secret_integrity_check

  def create_integrity_check(self, secret):
    """
    From the provided secret, create the secret integrity check
    by computing the strecthed hash of the password.
    """
    secret_length = self.secret_length
    verification_iterations = self.recombination_iterations

    if self.shamirsecretobj is None:
        return None

    secret_hash = sha256(secret)
    for coefficient in self.shamirsecretobj._coefficients:
        secret_hash.update(coefficient[:self.threshold])

    secret_digest = secret_hash.digest()

    # For some reason, Lagrange Recombination pads with a 0 at the
    # end of each coefficient, so I'll truncate to the size of the
    # threshold (it seems to be consistent in that length).
    for i in range(1, verification_iterations):
        secret_digest = sha256(secret_digest).digest()

    return secret_digest

  def create_secret(self):
    """
    Returns a random string of SECRET_LENGTH bytes
    """
    secret_length = self.secret_length
    verification_iterations = self.recombination_iterations

    secret = os.urandom(secret_length)

    return secret

  def create_isolated_validation_bits(self, passhash):
    """
    Returns the isolated-check bits suffix to add to an existing
    passhash
    """
    icbs = self.isolated_check_bits
    icb_iterations = self.icb_iterations

    for i in range(1, icb_iterations):
      passhash = sha256(passhash).digest()

    return passhash[len(passhash)-icbs:]





#### Private helper...
def _do_bytearray_XOR(a,b):
  a = bytearray(a)
  b = bytearray(b)

  # should always be true in our case...
  if len(a) != len(b):
    print len(a), len(b), a, b
  assert(len(a) == len(b))
  result = bytearray()

  for pos in range(len(a)):
    result.append(a[pos]^b[pos])

  return result

