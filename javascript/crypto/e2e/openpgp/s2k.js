// Copyright 2012 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * @fileoverview Implements RFC 4880 String to Key specification.
 * @author evn@google.com (Eduardo Vela)
 */

goog.provide('e2e.openpgp.IteratedS2K');
goog.provide('e2e.openpgp.S2k');
goog.provide('e2e.openpgp.SaltedS2K');
goog.provide('e2e.openpgp.SimpleS2K');


goog.require('e2e');
goog.require('e2e.openpgp.constants');
goog.require('e2e.openpgp.constants.Type');
goog.require('e2e.openpgp.error.InvalidArgumentsError');
goog.require('e2e.openpgp.error.ParseError');


/**
 * Generates an S2K object with the specified type, salt and count as specified
 * in RFC 4880 Section 3.7. We have subclasses for the different types of S2K.
 * @param {e2e.hash.Hash} hash An instance of the hash algorithm to use.
 * @constructor
 */
e2e.openpgp.S2k = function(hash) {
  /**
   * An instance of the hash algorithm to use.
   * @type {e2e.hash.Hash}
   * @protected
   */
  this.hash = hash;
};


/**
 * Maximum number of bytes in salt.
 * @type {number}
 * @const
 */
e2e.openpgp.S2k.MAX_SALT_SIZE = 8;


/**
 * The different types of S2K algorithms.
 * @enum {number}
 */
e2e.openpgp.S2k.Type = {
  'SIMPLE': 0,
  'SALTED': 1,
  'ITERATED': 3
};


/**
 * The type of s2k algorithm to use.
 * @type {e2e.openpgp.S2k.Type}
 */
e2e.openpgp.S2k.prototype.type;


/**
 * Generates a key from the given input. To be implemented by the subclasses.
 * @param {e2e.ByteArray} passphrase A ByteArray representation of the
 *     passphrase (must be encoded in UTF-8).
 * @param {number} length The length of the key requested.
 * @return {e2e.ByteArray} The key generated from that passphrase using
 *     the S2K algorithm.
 */
e2e.openpgp.S2k.prototype.getKey = goog.abstractMethod;
e2e.openpgp.S2k.prototype.getKeySlow = goog.abstractMethod;



/**
 * Serializes the S2K object to a string.
 * @return {e2e.ByteArray} The serialized S2K.
 */
e2e.openpgp.S2k.prototype.serialize = function() {
  return goog.array.concat(
      this.type,
      e2e.openpgp.constants.getId(this.hash.algorithm));
};


/**
 * Parses (and extracts) an S2K object from the given ByteArray.
 * Throws e2e.openpgp.error.Error if it fails.
 * @param {e2e.ByteArray} bytes The ByteArray to extract the S2K from.
 * @return {e2e.openpgp.S2k} The generated S2K instance.
 */
e2e.openpgp.S2k.parse = function(bytes) {
  var type = bytes.shift();
  if (!goog.object.containsValue(e2e.openpgp.S2k.Type, type)) {
    throw new e2e.openpgp.error.ParseError('Invalid S2K type.');
  }
  type = /** @type {e2e.openpgp.S2k.Type} */ (type);
  var hid = bytes.shift();
  var hash = e2e.openpgp.constants.getInstance(
      e2e.openpgp.constants.Type.HASH, hid);
  hash = /** @type {e2e.hash.Hash} */ (hash);
  var salt, encodedCount;
  if (type === e2e.openpgp.S2k.Type.SALTED ||
      type === e2e.openpgp.S2k.Type.ITERATED) {
    salt = bytes.splice(0, 8);
    if (salt.length != 8) {
      throw new e2e.openpgp.error.ParseError('Invalid S2K packet.');
    }
    if (type === e2e.openpgp.S2k.Type.ITERATED) {
      encodedCount = bytes.shift();
      return new e2e.openpgp.IteratedS2K(hash, salt, encodedCount);
    } else {
      return new e2e.openpgp.SaltedS2K(hash, salt);
    }
  } else if (type === e2e.openpgp.S2k.Type.SIMPLE) {
    return new e2e.openpgp.SimpleS2K(hash);
  }
  // TODO(evn): Implement a scrypt KDF as a new S2K type.
  throw new e2e.openpgp.error.ParseError('Invalid S2K type.');
};



/**
 * Implements the Simple S2K algorithm.
 * @param {e2e.hash.Hash} hash An instance of the hash algorithm to use.
 * @constructor
 * @extends {e2e.openpgp.S2k}
 */
e2e.openpgp.SimpleS2K = function(hash) {
  goog.base(this, hash);
};
goog.inherits(e2e.openpgp.SimpleS2K, e2e.openpgp.S2k);


/** @inheritDoc */
e2e.openpgp.SimpleS2K.prototype.type = e2e.openpgp.S2k.Type.SIMPLE;


/** @inheritDoc */
e2e.openpgp.SimpleS2K.prototype.getKey = function(passphrase, length) {
  var hashed = [], original_length = length;
  while (length > 0) {
    // Hash the passphrase repeatedly by appending 0's at the begining.
    var checksum = this.hash.hash(passphrase);
    passphrase.unshift(0);
    length -= checksum.length;
    goog.array.extend(hashed, checksum);
  }
  return hashed.slice(0, original_length);
};



/**
 * Implements the Salted S2K algorithm. Throws e2e.openpgp.error.Error if it
 * fails.
 * @param {e2e.hash.Hash} hash An instance of the hash algorithm to use.
 * @param {e2e.ByteArray} salt The salt to use for the S2K.
 * @constructor
 * @extends {e2e.openpgp.SimpleS2K}
 */
e2e.openpgp.SaltedS2K = function(hash, salt) {
  goog.base(this, hash);
  if (!e2e.isByteArray(salt)) {
    throw new e2e.openpgp.error.InvalidArgumentsError('Invalid salt.');
  }
  /**
   * The salt for the key.
   * @type {e2e.ByteArray}
   * @private
   */
  this.salt_ = salt;
};
goog.inherits(e2e.openpgp.SaltedS2K, e2e.openpgp.SimpleS2K);


/** @inheritDoc */
e2e.openpgp.SaltedS2K.prototype.type = e2e.openpgp.S2k.Type.SALTED;


/** @inheritDoc */
e2e.openpgp.SaltedS2K.prototype.getKey = function(passphrase, length) {
  var salted_passphrase = this.salt_.concat(passphrase);
  return goog.base(this, 'getKey', salted_passphrase, length);
};


/** @inheritDoc */
e2e.openpgp.SaltedS2K.prototype.serialize = function() {
  return goog.array.concat(
      goog.base(this, 'serialize'),
      this.salt_);
};



/**
 * Implements the Iterated S2K algorithm. Throws e2e.openpgp.error.Error if
 * it fails.
 * @param {e2e.hash.Hash} hash An instance of the hash algorithm to use.
 * @param {e2e.ByteArray} salt The salt to use for the S2K.
 * @param {number} encodedCount The encoded number of bytes to be hashed.
 * @constructor
 * @extends {e2e.openpgp.SimpleS2K}
 */
e2e.openpgp.IteratedS2K = function(hash, salt, encodedCount) {
  goog.base(this, hash);
  // TODO(adhintz) See if salt length should be required to be 8. The RFC
  // specifies 8 bytes, but golang's tests use 4 byte salts.
  // TODO(dlg) Tell Drew Hintz that it should be 8 bytes. Fix golang.
  if (!e2e.isByteArray(salt)) {
    throw new e2e.openpgp.error.InvalidArgumentsError('Invalid salt.');
  }
  if (!e2e.isByte(encodedCount)) {
    throw new e2e.openpgp.error.InvalidArgumentsError(
      'Invalid encoded count.');
  }
  /**
   * The salt to use for the S2K. Must be 8 bytes long.
   * @type {e2e.ByteArray}
   * @private
   */
  this.salt_ = salt;
  /**
   * The encoded number of bytes to be hashed.
   * @type {number}
   * @private
   */
  this.encodedCount_ = encodedCount;
  /**
   * The decoded number of bytes to be hashed.
   * @type {number}
   * @private
   */
  this.count_ = e2e.openpgp.IteratedS2K.getCount_(encodedCount);
};
goog.inherits(e2e.openpgp.IteratedS2K, e2e.openpgp.SimpleS2K);

/** @inheritDoc */
e2e.openpgp.IteratedS2K.prototype.type = e2e.openpgp.S2k.Type.ITERATED;

e2e.openpgp.IteratedS2K.prototype.getKeyFast_ = function(salted_passphrase, count) {
  this.hash.reset();
  // TODO(dlg): why does `this.hash.block_size` not work?
  // 64 bytes for SHA1, SHA2-256; 128 bytes for SHA2-512
  var block_size = 64;
  var reps = goog.math.safeCeil(block_size / salted_passphrase.length) + 1;
  var block = goog.array.flatten(goog.array.repeat(salted_passphrase, reps));
  //console.log("block", block, "block.length", block.length);
  var i = 0;
  while (i < count) {
    var imods = goog.math.modulo(i, salted_passphrase.length);
    var uplen = (block_size < count) ? block_size : count;
    //console.log("imods", imods, "uplen", uplen, "i", i);
    this.hash.update(
      block.slice(imods, imods+uplen));
    i = i + uplen;
  }
  var checksum = this.hash.digest();
  return checksum;
};

/* TODO(dlg): Remove after further performance improvements. */
e2e.openpgp.IteratedS2K.prototype.getKeySlow = function(passphrase, length) {
  var salted_passphrase = this.salt_.concat(passphrase);
  var count = this.count_;

  if (count < salted_passphrase.length) {
    count = salted_passphrase.length;
  }

  var num_zero_prepend = 0;
  var hashed = [], original_length = length;
  var i = 0;
  while (length > 0) { // Loop to handle when checksum len < length requested.
    console.log(i);
    i += 1;
    var iterated_passphrase_length = 0;
    this.hash.reset();
    this.hash.update(goog.array.repeat(0, num_zero_prepend));
    while (iterated_passphrase_length < count) {
      this.hash.update(
          salted_passphrase.slice(0, count - iterated_passphrase_length));
      // Might have added fewer bytes, but it's just an exit condition.
      iterated_passphrase_length += salted_passphrase.length;
    }
    var checksum = this.hash.digest();
    length -= checksum.length;
    goog.array.extend(hashed, checksum);
    num_zero_prepend += 1;
  }
  return hashed.slice(0, original_length);
};


/** @inheritDoc */
e2e.openpgp.IteratedS2K.prototype.getKey = function(passphrase, length) {
  var salted_passphrase = this.salt_.concat(passphrase);
  var count = this.count_;

  if (count < salted_passphrase.length) {
    count = salted_passphrase.length;
  }

  // TODO(dlg): Is there a less stupid way of finding out the length?
  this.hash.reset();
  var digest_length = this.hash.digest().length;

  if ((salted_passphrase.length < 64) && (digest_length >= length)) {
    return this.getKeyFast_(salted_passphrase, count).slice(0, length);
  }

  var num_zero_prepend = 0;
  var hashed = [], original_length = length;
  while (length > 0) { // Loop to handle when checksum len < length requested.
    var iterated_passphrase_length = 0;
    this.hash.reset();
    this.hash.update(goog.array.repeat(0, num_zero_prepend));
    while (iterated_passphrase_length < count) {
      this.hash.update(
          salted_passphrase.slice(0, count - iterated_passphrase_length));
      // Might have added fewer bytes, but it's just an exit condition.
      iterated_passphrase_length += salted_passphrase.length;
    }
    var checksum = this.hash.digest();
    length -= checksum.length;
    goog.array.extend(hashed, checksum);
    num_zero_prepend += 1;
  }
  return hashed.slice(0, original_length);
};


/** @inheritDoc */
e2e.openpgp.IteratedS2K.prototype.serialize = function() {
  return goog.array.concat(
      goog.base(this, 'serialize'),
      this.salt_,
      this.encodedCount_);
};


/**
 * The EXPBIAS constant as defined in RFC 4880 Section 3.7.1.3.
 * @type {number}
 * @const
 * @private
 */
e2e.openpgp.IteratedS2K.EXPBIAS_ = 6;


/**
 * Returns the number of iterations for a given count using the algorithm
 * defined in RFC 4880 Section 3.7.1.3. Must be in the range [0-255].
 * Throws e2e.openpgp.error.Error if it fails.
 * @param {number} c The encoded count for.
 * @return {number} The number of bytes to be hashed.
 * @private
 */
e2e.openpgp.IteratedS2K.getCount_ = function(c) {
  if (e2e.isByte(c)) {
    return (0x10 + (c & 0x0F)) << ((c >> 4) +
                                   e2e.openpgp.IteratedS2K.EXPBIAS_);
  } else {
    throw new e2e.openpgp.error.InvalidArgumentsError(
      'Invalid encoded count.');
  }
};
