""" 
<Author>
  Justin Cappos

<Start Date>
  May 25th, 2011

<Description>
  A wrapper for a C-based datastore.   This uses objects, etc. to make 
  the C interface more Pythonic...

  This is really just a version of the Python datastore with the Python code 
  replaced with the C extension.   I left in all of the error checking.
  

"""

import fastsimplexordatastore_c
import math


def do_xor(string_a, string_b):
  if type(string_a) != str or type(string_b) != str:
    raise TypeError("do_xor called with a non-string")

  if len(string_a) != len(string_b):
    raise ValueError("do_xor requires strings of the same length")

  return fastsimplexordatastore_c.do_xor(string_a,string_b)


class XORDatastore:
  """
  <Purpose>
    Class that has information for an XORdatastore.   This data structure can
    quickly XOR blocks of data that it stores.   The real work is done in a
    C extension

  <Side Effects>
    None.

  """

  # this is the private, internal storage area for data...
  ds = None

  # these are public so that a caller can read information about a created
  # datastore.   They should not be changed.   
  numberofblocks = None
  sizeofblocks = None
 
  def __init__(self, block_size, num_blocks):  # allocate
    """
    <Purpose>
      Allocate a place to store data for efficient XOR.   

    <Arguments>
      block_size: the size of each block.   This must be a positive int / long.
                  The value must be a multiple of 64
      
      num_blocks: the number of blocks.   This must be a positive integer

    <Exceptions>
      TypeError is raised if invalid parameters are given.

    """

    if type(block_size) != int and type(block_size) != long:
      raise TypeError("Block size must be an integer")

    if block_size <= 0:
      raise TypeError("Block size must be positive")

    if block_size %64 != 0:
      raise TypeError("Block size must be a multiple of 64")

    if type(num_blocks) != int and type(num_blocks) != long:
      raise TypeError("Number of blocks must be an integer")

    if num_blocks <= 0:
      raise TypeError("Number of blocks must be positive")


    self.numberofblocks = num_blocks
    self.sizeofblocks = block_size

    self.ds = fastsimplexordatastore_c.Allocate(block_size, num_blocks)
    

  def produce_xor_from_bitstring(self, bitstring):
    """
    <Purpose>
      Returns an XORed block from an XORdatastore.   It will always return
      a string of the size of the datastore blocks

    <Arguments>
      bitstring: a string of bits that indicates what to XOR.   The length
                 of this string must be ceil(numberofblocks / 8.0).   Extra
                 bits are ignored (e.g. if are 10 blocks, the last
                 six bits are ignored).
      
    <Exceptions>
      TypeError is raised if the bitstring is invalid

    <Returns>
      The XORed block.

    """
    if type(bitstring) != str:
      raise TypeError("bitstring must be a string")

    if len(bitstring) != math.ceil(self.numberofblocks/8.0):
      raise TypeError("bitstring is not of the correct length")


    return fastsimplexordatastore_c.Produce_Xor_From_Bitstring(self.ds, bitstring)
      



  def set_data(self, offset, data_to_add):
    """
    <Purpose>
      Sets the raw data in an XORdatastore.   It ignores block layout, etc.

    <Arguments>
      offset: this is a non-negative integer that must be less than the 
              numberofblocks * blocksize.   
      
      data_to_add: the string that should be added.   offset + len(data_to_add)
                must be less than the numberofblocks * blocksize.
      
    <Exceptions>
      TypeError if the arguments are the wrong type or have invalid values.

    <Returns>
      None

    """
    if type(offset) != int and type(offset) != long:
      raise TypeError("Offset must be an integer")

    if offset < 0:
      raise TypeError("Offset must be non-negative")

    if type(data_to_add) != str:
      raise TypeError("Data_to_add to XORdatastore must be a string.")

    if offset + len(data_to_add) > self.numberofblocks * self.sizeofblocks:
      raise TypeError("Offset + added data overflows the XORdatastore")

    return fastsimplexordatastore_c.SetData(self.ds, offset, data_to_add)
    






  def get_data(self, offset, quantity):
    """
    <Purpose>
      Returns raw data from an XORdatastore.   It ignores block layout, etc.

    <Arguments>
      offset: this is a non-negative integer that must be less than the 
              numberofblocks * blocksize.   
      
      quantity: quantity must be a positive integer.   offset + quantity 
                must be less than the numberofblocks * blocksize.
      
    <Exceptions>
      TypeError if the arguments are the wrong type or have invalid values.

    <Returns>
      A string containing the data.

    """
    if type(offset) != int and type(offset) != long:
      raise TypeError("Offset must be an integer")

    if offset < 0:
      raise TypeError("Offset must be non-negative")

    if type(quantity) != int and type(quantity) != long:
      raise TypeError("Quantity must be an integer")

    if quantity <= 0:
      raise TypeError("Quantity must be positive")

    if offset + quantity > self.numberofblocks * self.sizeofblocks:
      raise TypeError("Quantity + offset is larger than XORdatastore")

    return fastsimplexordatastore_c.GetData(self.ds, offset, quantity)





  def __del__(self):   # deallocate
    """
    <Purpose>
      Deallocate the XORdatastore

    <Arguments>
      None

    <Exceptions>
      None

    """
    # if there is an error, this might be an uninitialized object...
    if self.ds != None:
      fastsimplexordatastore_c.Deallocate(self.ds)


