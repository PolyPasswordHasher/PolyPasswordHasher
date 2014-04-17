require 'minitest/unit'
require 'minitest/autorun'
require File.expand_path("../../polypasshash.rb", __FILE__)

class TestPolyPassHash < MiniTest::Unit::TestCase
  THRESHOLD = 10
  def setup
    @pph = PolyPassHash.new(THRESHOLD, nil)
  end
  
  def test_create_account
    @pph.create_account('admin', 'correct horse', THRESHOLD/2)
    @pph.create_account('root','battery staple',THRESHOLD/2)
    @pph.create_account('superuser','purple monkey dishwasher',THRESHOLD/2)

    @pph.create_account('alice','kitten',1)
    @pph.create_account('bob','puppy',1)
    @pph.create_account('charlie','velociraptor',1)
    @pph.create_account('dennis','menace',0)
    @pph.create_account('eve','iamevil',0)

    assert(@pph.is_valid_login('alice', 'kitten'))
    assert(@pph.is_valid_login('admin', 'correct horse'))
    assert(@pph.is_valid_login('alice', 'nyancat!') == false)
    assert(@pph.is_valid_login('dennis', 'menace'))
    assert(@pph.is_valid_login('dennis', 'password') == false)

  end

  def test_unlock_password_data
    @pph.create_account('admin', 'correct horse', THRESHOLD/2)
    @pph.create_account('root','battery staple',THRESHOLD/2)
    @pph.create_account('superuser','purple monkey dishwasher',THRESHOLD/2)
    @pph.create_account('alice','kitten',1)
    @pph.write_password_data('securepasswords_ruby')
    @pph = nil

    @pph = PolyPassHash.new(THRESHOLD, 'securepasswords_ruby') 
    assert_raises ValueError do 
      @pph.is_valid_login('alice', 'kitten')
    end

    assert(@pph.unlock_password_data([['admin','correct horse'], ['root','battery staple']]))
  end

  def test_partial_valification
    @pph = PolyPassHash.new(THRESHOLD, nil, 2)

    @pph.create_account('admin', 'correct horse', THRESHOLD/2)
    @pph.create_account('root','battery staple',THRESHOLD/2)
    @pph.create_account('superuser','purple monkey dishwasher',THRESHOLD/2)

    @pph.create_account('alice','kitten',1)
    @pph.create_account('bob','puppy',1)
    @pph.create_account('charlie','velociraptor',1)
    @pph.create_account('dennis','menace',0)
    @pph.create_account('eve','iamevil',0)

    assert(@pph.is_valid_login('alice', 'kitten'))
    assert(@pph.is_valid_login('admin', 'correct horse'))
    assert(@pph.is_valid_login('alice', 'nyancat!') == false)
    assert(@pph.is_valid_login('dennis', 'menace'))
    assert(@pph.is_valid_login('dennis', 'password') == false)

    @pph.write_password_data('securepasswords_ruby')
    @pph = nil

    @pph = PolyPassHash.new(THRESHOLD, 'securepasswords_ruby', 2)

    assert(@pph.is_valid_login('alice', 'kitten'))
    assert(@pph.is_valid_login('admin', 'correct horse'))
    assert(@pph.is_valid_login('alice', 'nyancat!') == false)
  end
end


