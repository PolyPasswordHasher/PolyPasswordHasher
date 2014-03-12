/* Author: Justin Cappos
 * Inspired by code from Geremy Condra
 * File: fastsimplexordatastore.h
 * Purpose: The header file for the fastsimplexordatastore
 */

#include "Python.h"
// Needed for uint64_t on some versions of Python / GCC
#include <stdint.h>

typedef int datastore_descriptor;

typedef struct {
  long numberofblocks;      // Blocks in the datastore
  long sizeofablock;        // Bytes in a block.   
  char *raw_datastore;  // This points to what malloc returns...
  uint64_t *datastore;      // This is the DWORD aligned start to the datastore
} XORDatastore;

// Define all of the functions...

static inline void XOR_fullblocks(uint64_t *dest, uint64_t *data, long count);
static inline void XOR_byteblocks(char *dest, const char *data, long count);
static inline char *dword_align(char *ptr);
static int is_table_entry_used(int i);
static datastore_descriptor allocate(long block_size, long num_blocks);
static PyObject *Allocate(PyObject *module, PyObject *args);
static void bitstring_xor_worker(int ds, char *bit_string, long bit_string_length, uint64_t *resultbuffer);
static PyObject *Produce_Xor_From_Bitstring(PyObject *module, PyObject *args);
static PyObject *SetData(PyObject *module, PyObject *args);
static PyObject *GetData(PyObject *module, PyObject *args);
static void deallocate(datastore_descriptor ds);
static PyObject *Deallocate(PyObject *module, PyObject *args);
static char *slow_XOR(char *dest, const char *data, long stringlength);
static char *fast_XOR(char *dest, const char *data, long stringlength);
static PyObject *do_xor(PyObject *module, PyObject *args);
