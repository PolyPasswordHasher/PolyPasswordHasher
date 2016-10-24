import polypasswordhasher

import time
import sys

######################## Init time (incorrect) #######################

for THRESHOLD in [1,2,4,8,16,32,64,128,253]:
  # the purpose of this is to do timing tests.   I'll use the same account data 

  count = 100
  starttime= time.time()
  for num in range(count):
    pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD, passwordfile = None)
  endtime = time.time()

  print "Full initialization time T "+str(THRESHOLD)+" "+str((endtime-starttime)/count)


######################## Creation time #######################

for THRESHOLD in [1,2,4,8,16,32,64,128,253]:

  pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD, passwordfile = None)

  # create three admins so that any two have the appropriate threshold
  pph.create_account('admin','correct horse',THRESHOLD/2)


  count = 100
  starttime= time.time()
  for num in range(count):
    pph.create_account('alice'+str(num),'kitten',1)
  endtime = time.time()

  print "Full account create time T "+str(THRESHOLD)+" "+str((endtime-starttime)/count),"perf:",1/((endtime-starttime)/count)

  # try some logins and make sure we see what we expect...
  assert(pph.is_valid_login('alice1','kitten') == True)
  assert(pph.is_valid_login('alice1','nyancat!') == False)




######################## Creation time (thresholdless) #######################

for THRESHOLD in [1,2,4,8,16,32,64,128,253]:

  pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD, passwordfile = None)

  # create three admins so that any two have the appropriate threshold
  pph.create_account('admin','correct horse',THRESHOLD)


  count = 100
  starttime= time.time()
  for num in range(count):
    pph.create_account('alice'+str(num),'kitten',0)
  endtime = time.time()

  print "Full thresholdless account create time T "+str(THRESHOLD)+" "+str((endtime-starttime)/count),"perf:",1/((endtime-starttime)/count)

  # try some logins and make sure we see what we expect...
  assert(pph.is_valid_login('alice1','kitten') == True)
  assert(pph.is_valid_login('alice1','nyancat!') == False)







######################## Check time (incorrect) #######################


for THRESHOLD in [1,2,4,8,16,32,64,128,253]:

  pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD, passwordfile = None)

  # create three admins so that any two have the appropriate threshold
  pph.create_account('admin','correct horse',THRESHOLD)
  pph.create_account('alice1','kitten',1)

  count = 100
  starttime= time.time()
  for num in range(count):
    pph.is_valid_login('alice1','puppy')
  endtime = time.time()

  print "Full account (miss) check time T "+str(THRESHOLD)+" "+str((endtime-starttime)/count),"perf:",1/((endtime-starttime)/count)



######################## Check time (correct) #######################

for THRESHOLD in [1,2,4,8,16,32,64,128,253]:

  pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD, passwordfile = None)

  # create three admins so that any two have the appropriate threshold
  pph.create_account('admin','correct horse',THRESHOLD)
  pph.create_account('alice1','kitten',1)

  count = 100
  starttime= time.time()
  for num in range(count):
    pph.is_valid_login('alice1','kitten')
  endtime = time.time()

  print "Full account (correct) check time T "+str(THRESHOLD)+" "+str((endtime-starttime)/count),"perf:",1/((endtime-starttime)/count)


######################## Check time (thresholdless) #######################


for THRESHOLD in [1,2,4,8,16,32,64,128,253]:

  pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD, passwordfile = None)

  # create three admins so that any two have the appropriate threshold
  pph.create_account('admin','correct horse',THRESHOLD)
  pph.create_account('alice1','kitten',0)

  count = 100
  starttime= time.time()
  for num in range(count):
    pph.is_valid_login('alice1','kitten')
  endtime = time.time()

  print "Full account thresholdless hit check time T "+str(THRESHOLD)+" "+str((endtime-starttime)/count),"perf:",1/((endtime-starttime)/count)





######################## Accessing Stored Data Store #######################

#for THRESHOLD in [1,2,4,5,6,7,8,9,10,11,12,13,14,15,16,32,64,128,253]:
for THRESHOLD in [1,2,4,8,16,32,64,128,253]:

  pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD, passwordfile = None)

  # create three admins so that any two have the appropriate threshold
  pph.create_account('admin','correct horse',THRESHOLD)

  # persist the password file to disk
  pph.write_password_data('securepasswords')
 
  # If I remove this from memory, I can't use the data on disk to check 
  # passwords without a threshold
  pph = None

  # let's load it back in
  pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD,passwordfile = 'securepasswords')

  # The password information is essentially useless alone.   You cannot know
  # if a password is valid without threshold or more other passwords!!!
  try: 
    pph.is_valid_login('alice','kitten')
  except ValueError:
    pass
  else:
    print "Can't get here!   It's still locked!!!"

  starttime= time.time()
  # with a threshold (or more) of correct passwords, it decodes and is usable.
  pph.unlock_password_data([('admin','correct horse')])
  endtime = time.time()
  print "Accessing a stored data store time T "+str(THRESHOLD)+" "+str((endtime-starttime)), "perf:",THRESHOLD/(endtime-starttime)



######################## Salted Hash Verification Time #######################
from hashlib import sha256

count = 100
starttime= time.time()
for num in range(count):
  # assume I know the 16 byte hash
  salt = '0123456789abcdef'
  saltedpasswordhash = sha256(salt + 'kitten').digest()

endtime = time.time()

print "Salted Hash verification time "+str((endtime-starttime)/count),"perf:",1/((endtime-starttime)/count)


######################## Salted Hash Creation Time #######################
from hashlib import sha256
import os

count = 100
starttime= time.time()
for num in range(count):
  # generate a 16 byte hash
  salt = os.urandom(16)
  saltedpasswordhash = sha256(salt + 'kitten').digest()

endtime = time.time()

print "Salted Hash creation time "+str((endtime-starttime)/count),"perf:",1/((endtime-starttime)/count)

