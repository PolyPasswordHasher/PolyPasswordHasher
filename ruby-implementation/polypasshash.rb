require 'openssl'
require 'digest/sha1'
require 'digest/sha2'
require File.expand_path("../shamirsecret.rb", __FILE__)

class ValueError < Exception; end

class PolyPassHash
  def initialize(threshold, passwordfile=nil, partialbytes=0)
    @threshold = threshold
    @accountdict = {}
    @partialbytes = partialbytes
    @saltsize = 16
    @nextavailableshare = 1

    unless passwordfile
      @thresholdlesskey = OpenSSL::Random.random_bytes(32)
      @shamirsecretobj = ShamirSecret.new(threshold, @thresholdlesskey)
      @knownsecret = true
      @nextavailableshare = 1
      return
    end

    @shamirsecretobj = ShamirSecret.new(threshold)
    @knownsecret = false
    @thresholdlesskey = nil

    passwordfiledata = File.open(passwordfile){|f| f.read}
    @accountdict = Marshal.load(passwordfiledata)

    @accountdict.keys.each do |username|
      @accountdict[username].each do |share|  
        @nextavailableshare = [share['sharenumber'], @nextavailableshare].max
      end
    end

    @nextavailableshare += 1
  end

  def create_account(username, password, shares)
    raise ValueError, "Password file is not unlocked!!" unless @knownsecret
    raise ValueError, "Username exists already!" if @accountdict.has_key?(username)
    raise ValueError, "Invalid number of shares: #{shares}." if shares + @nextavailableshare > 255
    @accountdict[username] = []

    if shares == 0
      thisentry = {}
      thisentry['sharenumber'] = 0
      thisentry['salt'] = OpenSSL::Random.random_bytes(@saltsize)
      saltedpasswordhash = Digest::SHA256.digest(thisentry['salt']+password)

      cipher = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
      cipher.encrypt
      cipher.pkcs5_keyivgen(@thresholdlesskey)
      thisentry['passhash'] = cipher.update(saltedpasswordhash) + cipher.final
      thisentry['passhash'] += saltedpasswordhash[(saltedpasswordhash.size - @partialbytes)..-1]

      
      @accountdict[username] << thisentry
      return true
    end

    (@nextavailableshare..(@nextavailableshare+shares-1)).each do |sharenumber|
      thisentry = {}
      thisentry['sharenumber'] = sharenumber
      shamirsecretdata = @shamirsecretobj.compute_share(sharenumber)[1]
      thisentry['salt'] = OpenSSL::Random.random_bytes(@saltsize)
      saltedpasswordhash = Digest::SHA256.digest(thisentry['salt']+password)
      thisentry['passhash'] = _do_bytearray_XOR(saltedpasswordhash, shamirsecretdata)
      thisentry['passhash'] += saltedpasswordhash[(saltedpasswordhash.size - @partialbytes)..-1]

      @accountdict[username] << thisentry
    end

    @nextavailableshare += shares

  end

  def is_valid_login(username, password)
    raise ValueError, "Password file is not unlocked and partial verification is disabled!!" if @knownsecret == false && @partialbytes == 0
    raise "Unknown user '#{username}'" unless @accountdict.has_key?(username)

    @accountdict[username].each do |entry|
      saltedpasswordhash = Digest::SHA256.digest(entry['salt']+password)

      unless @knownsecret
	if saltedpasswordhash[(saltedpasswordhash.size - @partialbytes)..-1] == entry['passhash'][(entry['passhash'].size)-@partialbytes..-1]
	  return true
	else
	  return false
	end
      end

      sharedata = _do_bytearray_XOR(saltedpasswordhash, entry['passhash'][0..(entry['passhash'].size-1)-@partialbytes])

      if entry['sharenumber'].to_i == 0
        cipher = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
        cipher.encrypt
        cipher.pkcs5_keyivgen(@thresholdlesskey)
        enc = cipher.update(saltedpasswordhash) + cipher.final

	if enc == entry['passhash'][0..entry['passhash'].size-1-@partialbytes]
	  return true
	else
	  return false
	end
      end

      share = [entry['sharenumber'], sharedata.bytes.to_a]

      return @shamirsecretobj.is_valid_share(share)
    end
  end

  def write_password_data(passwordfile)
    raise ValueError, "Would write undecodabale password file. Must have more shares before writing." if @threshold >= @nextavailableshare
    File.open(passwordfile, "w") {|f| Marshal.dump(@accountdict, f)}
  end

  def unlock_password_data(logindata)
    raise ValueError, "Password file is already unlocked!" if @knownsecret

    sharelist = []

    logindata.each do |data|
      username = data[0]
      password = data[1]

      raise ValueError, "Unknown user '#{username}'" unless @accountdict.has_key?(username)

      @accountdict[username].each do |entry|
	next if entry['sharenumber'] == 0

	thissaltedpasswordhash = Digest::SHA256.digest(entry['salt']+password)
	thisshare = [entry['sharenumber'], _do_bytearray_XOR(thissaltedpasswordhash, entry['passhash'][0..(entry['passhash'].size-1)-@partialbytes])]

	sharelist << thisshare
      end

    end

    @shamirsecretobj.recover_secretdata(sharelist)
    @thresholdlesskey = @shamirsecretobj.secretdata
    @knownsecret = true
  end

  private 
  
  def _do_bytearray_XOR(a,b)
    result = []

    bytesize = a.size
    a = a.bytes.to_a if a.class != Array
    b = b.bytes.to_a if b.class != Array

    bytesize.times do |i|
      result << (a[i] ^ b[i])
    end

    result.map {|r| r.chr}.join
  end

end
