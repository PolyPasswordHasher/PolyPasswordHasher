require 'minitest/unit'
require 'minitest/autorun'
require File.expand_path("../../shamirsecret.rb", __FILE__) 

class TestShamirSecret < MiniTest::Unit::TestCase
  def setup
    @shamirsecretobj = ShamirSecret.new(2, "hello")
  end

  def test_multiply_polynomials
    assert_equal([4,9,31,20], @shamirsecretobj.send(:_multiply_polynomials, [1,3,4],[4,5]) )
  end

  def test_full_lagrange
    assert_equal([43, 168, 150], @shamirsecretobj.send(:_full_lagrange, [2,4,5],[14,30,32]) )
  end

  def test_compute_share
    a = @shamirsecretobj.compute_share(1)
    b = @shamirsecretobj.compute_share(2)
    c = @shamirsecretobj.compute_share(3)

    t = ShamirSecret.new(2)
    assert(t.recover_secretdata([a,b]))

    t = ShamirSecret.new(2)
    assert(t.recover_secretdata([a,c]))

    t = ShamirSecret.new(2)
    assert(t.recover_secretdata([b,c]))

    t = ShamirSecret.new(2)
    assert(t.recover_secretdata([a,b,c]))
  end

  def test_is_valid_share
    shamirsecretobj = ShamirSecret.new(2, "my shared secret")
    a = shamirsecretobj.compute_share(4)
    b = shamirsecretobj.compute_share(6)
    c = shamirsecretobj.compute_share(1)
    d = shamirsecretobj.compute_share(2)
    newsecret = ShamirSecret.new(2)
    newsecret.recover_secretdata([a,b,c])

    assert(newsecret.is_valid_share(d))
  end
  
end

