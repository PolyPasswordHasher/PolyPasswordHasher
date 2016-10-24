import polypasswordhasher

import time
import sys

# the purpose of this is to do timing tests.   I'll use the same account data 
# as before.
THRESHOLD = int(sys.argv[1])

count = 100
starttime= time.time()
for num in range(count):
  pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD, passwordfile = None)

print "Full initialization time: "+str((time.time()-starttime)/count)


# require knowledge of 10 shares to decode others.   Create a blank, new
# password file...
pph = polypasswordhasher.PolyPasswordHasher(threshold = THRESHOLD, passwordfile = None)

# create three admins so that any two have the appropriate threshold
pph.create_account('admin','correct horse',THRESHOLD/2)
pph.create_account('root','battery staple',THRESHOLD/2)
pph.create_account('superuser','purple monkey dishwasher',THRESHOLD/2)


pph.create_account('alice','kitten',1)
pph.create_account('bob','puppy',1)
pph.create_account('charlie','velociraptor',1)


count = 100
starttime= time.time()
for num in range(count):
  pph.create_account('alice'+str(num),'kitten',1)

print "Full account create time: "+str((time.time()-starttime)/count)

# try some logins and make sure we see what we expect...
assert(pph.is_valid_login('alice','kitten') == True)
assert(pph.is_valid_login('admin','correct horse') == True)
assert(pph.is_valid_login('alice','nyancat!') == False)

count = 100
starttime= time.time()
for num in range(count):
  pph.is_valid_login('bob','puppy')

print "Full account check time: "+str((time.time()-starttime)/count)

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
pph.unlock_password_data([('admin','correct horse'), ('root','battery staple'), ('bob','puppy')])
print "Accessing a stored data store time: "+str((time.time()-starttime))

# now, I can do the usual operations with it...
assert(pph.is_valid_login('alice','kitten') == True)

pph.create_account('dennis','tadpole',1)


