/**
 * Raw Paillier Cryptoscheme
 * @module paillier
 * @fileOverview A Paillier Cryptoscheme implementation compatible with Python-Paillier.
 * @version 1.1.1
 * @author Brian Thorne <brian.thorne@nicta.com.au>
 *
 * @example
 *
 *var paillier = require("paillier");
 * // Create a new Paillier keypair
 * var keypair = paillier.generate_paillier_keypair();
 * keypair.public_key.encrypt("1")
 */

var bn = require('jsbn');
var crypto = require('crypto');
/**
 * Random number generator using node's crypto.rng
 * @private
 * @todo Ensure it works it the browser too
 */
function SecureRandom() {
    return {
        nextBytes: function (ba) {
            // returns a "SlowBuffer" of given length
            // can be cast to an ArrayBuffer
            // var ab = new Uint8Array(buf)
            var i;
            var n = ba.length;
            var buf = crypto.rng(n);
            for (i = 0; i < n; ++i) {
                ba[i] = buf[i];
            }
            return ba;
        }
    };
}
var rng = SecureRandom();
/**
 * Convert a {@link NumberLike} into a {@link external:BigInteger}.
 * @private
 * @param {NumberLike} input - The value to be converted into a BigInteger instance.
 * @returns {BigInteger}
 */


function convertToBN(input) {
    // Todo use instanceof as well?

    if (typeof input == "number") {
        console.log('WARNING: you appear to be using javascript numbers for cryptography');

        input = input.toString();

    }
    if (typeof input == "string") {
        //console.log("Converting input string to BigInteger");
        input = new bn(input, 10);
    }
    return input;
}
/** The natural logarithm of x
 * @see https://stackoverflow.com/questions/29418957/is-it-possible-to-get-a-natural-log-of-a-big-integer-instance
 * */
function bigIntegerLog(x) {
    console.log("TODO TODO TODO");
    return x;
}
/**
 * Create a Private Key.
 *
 * @namespace PrivateKey
 * @constructs PrivateKey
 *
 * @param {NumberLike} lambda - part of the public key - see Paillier's paper.
 * @param {NumberLike} mu - part of the public key - see Paillier's paper.
 * @param {PublicKey} public_key - The corresponding public key.
 *
 * */
var PrivateKey = (function () {
    function PrivateKey(lambda, mu, public_key) {
        this.public_key = public_key;
        this.lambda = convertToBN(lambda);
        this.mu = convertToBN(mu);
    }
    PrivateKey.prototype.toJSON = function () {
        // Override JSON routine to convert the BigIntegers into strings
        return {
            lambda: this.lambda.toString(),
            mu: this.mu.toString()
        };
    };
    ;
    PrivateKey.prototype.raw_decrypt = function (ciphertext) {
        // if plaintext isn't a bignum convert it...
        ciphertext = convertToBN(ciphertext);
        // TODO define output type string/Uint8Array/Buffer?
        var u = ciphertext.modPow(this.lambda, this.public_key.nsquare);
        var l_of_u = u.subtract(bn.ONE).divide(this.public_key.n);
        return l_of_u.multiply(this.mu).mod(this.public_key.n);
    };
    ;
    return PrivateKey;
})();
exports.PrivateKey = PrivateKey;
;
/**
 * Create a Public Key.
 *
 * @example
 * var publicKey = phe.publicKey("6497955158", "126869");
 *
 * @namespace PublicKey
 * @constructs PublicKey
 *
 * @param {NumberLike} g
 * @param {NumberLike} n
 *
 * @returns {PublicKey}
 */
var PublicKey = (function () {
    function PublicKey(g, n) {
        this.g = convertToBN(g);
        this.n = convertToBN(n);
        console.log('g  '+this.g);
        console.log('n  '+this.n);
        this.nsquare = n.multiply(n);
        this.max_int = n.divide(new bn("3", 10)).subtract(bn.ONE);
    }
    /* Return an integer number between 1 and n */
    PublicKey.prototype.get_random_lt_n = function () {
        var r;
        do {
            //r = new bn(1 + Math.log(this.n)/Math.LN2, 1, rng);
            r = new bn(bn.ONE.add(bigIntegerLog(this.n).divide(new bn(Math.LN2.toString()))), 1, rng);
        } while (r.compareTo(this.n) <= 0);
        return r;
    };
    /**
     * Raw paillier encryption of a positive integer plaintext.
     *
     * You probably want to use {@link encrypt} instead, because
     * it handles signed integers as well as floats.
     *
     * @param {NumberLike} plaintext - a positive integer. Typically an encoding of the actual value.
     * @param {NumberLike} [r_value] - obfuscator for the ciphertext. By default a random value is used.
     * @returns {BigInteger} ciphertext
     */
    PublicKey.prototype.raw_encrypt = function (plaintext_in, r_value_in) {
        // if plaintext isn't a bignum convert it...
        var plaintext = convertToBN(plaintext_in);
        var r_value = convertToBN(r_value_in);

        var nude_ciphertext;
        if ((this.n.subtract(this.max_int).compareTo(plaintext) <= 0) && (plaintext < this.n)) {
            var neg_plaintext = this.n.subtract(plaintext);
            var neg_ciphertext = this.g.modPow(neg_plaintext, this.nsquare);
            nude_ciphertext = neg_ciphertext.modInverse(this.nsquare);
        }
        else {
            nude_ciphertext = this.g.modPow(plaintext, this.nsquare);
        }
        if (typeof r_value === "undefined") {
            r_value = this.get_random_lt_n();
        }
        var obfuscator = r_value.modPow(this.n, this.nsquare);
        return nude_ciphertext.multiply(obfuscator).mod(this.nsquare);
    };
    ;
    /**
     * Encode and encrypt a signed int or float value.
     *
     * @param {number|float} value - an int or float to be encrypted.
     *      If int, it must satisfy abs(value) < n/3
     *      If float, it must satisfy abs(value/precision) << n/3
     * @param {float} precision - Passed to {@link EncodedNumber.encode}.
     * @param {?} [r_value] -
     *
     * @returns {EncryptedNumber} The encrypted number instance
     *
     * @TODO finish documenting and implementing me
     */
    PublicKey.prototype.encrypt = function (value, precision, r_value) {
        //var encoding = EncodedNumber.encode(this, value, precision);
        console.log("TOOD");
    };
    ;
    /**
     * Create a json serialization
     * @function
     * @returns {string} The JSON representation of the Public Key. Comprises
     *      g and n attributes.
     */
    PublicKey.prototype.toJSON = function () {
        return {
            g: this.g.toString(),
            n: this.n.toString()
        };
    };
    ;
    return PublicKey;
})();
exports.PublicKey = PublicKey;
;
/**
 * Return a random N-bit prime number using the System's best
 * Cryptographic random source.
 * @private
 * @param {NumberLike} bitLength - n-bit prime number
 */
function getprimeover(bitLength) {
    function getNBitRand(n) {
        return new bn(n, 1, rng);
    }
    var p = bn.ZERO;
    while (!p.isProbablePrime(20)) {
        p = getNBitRand(bitLength);
    }
    return p;
}
/**
 * Generate a Paillier KeyPair of given strength.
 *
 * @param {NumberLike} [n_length=1024] - key size in bits
 *
 * @example
 *
 * // Create a default keypair public, private:
 * var keypair = paillier.generate_paillier_keypair();
 *
 * @returns {KeyPair} KeyPair
 */
function generate_paillier_keypair(n_length) {
    var keysize;
    if (typeof n_length === "undefined") {
        keysize = 1024;
        console.log("Using default key size of " + keysize + " bits");
    }
    else {
        keysize = n_length;
    }
    console.log("Generating new keypair with " + keysize + " bit length key");
    var p, q, n, g, phi_n, mu;
    var correctLength = false;
    while (!correctLength || p.compareTo(q) == 0) {
        p = getprimeover(keysize >> 1);
        q = getprimeover(keysize >> 1);
        n = p.multiply(q);
        correctLength = n.testBit(keysize - 1);
    }
    // simple paillier variant with g=n+1
    g = n.add(bn.ONE);
    phi_n = p.subtract(bn.ONE).multiply(q.subtract(bn.ONE));
    mu = phi_n.modInverse(n);
    var pubKey = new PublicKey(g, n);
    return {
        public_key: pubKey,
        private_key: new PrivateKey(phi_n, mu, pubKey),
        n_length: keysize
    };
}
exports.generate_paillier_keypair = generate_paillier_keypair;
;
var EncodedNumber = (function () {
    /**
     * Represents a float or int encoded for Paillier encryption.
     *
     * For end users, this class is mainly useful for specifying precision
     * when adding/multiplying an {@link EncryptedNumber} by a scalar.
     *
     * If you want to manually encode a number for Paillier encryption,
     * then use encode, if de-serializing then use this constructor.
     *
     * @namespace EncodedNumber
     * @constructs EncodedNumber
     *
     * @param {PublicKey} public_key - public key for which to encode (this is necessary because max_int varies)
     * @param {BigInteger} encoding - The encoded number to store. Must be positive and less than max_int
     * @param {number} exponent - Together with the fixed BASE, determines the level of fixed-precision used
     *      in encoding the number.
     *
     * @returns {EncodedNumber}
     */
    function EncodedNumber(public_key, encoding, exponent) {
        this.public_key = public_key;
        this.exponent = exponent;
        this.encoding = convertToBN(encoding);
    }
    /** Compute the logarithm of x with given base */
    EncodedNumber.log = function (x, base) {
        return Math.log(x) / Math.log(base);
    };
    ;
    EncodedNumber.frexp_exponent = function (value) {
        // frexp separates a float into its mantissa and exponent
        if (value == 0.0)
            return 0; // zero is special
        var data = new DataView(new ArrayBuffer(8));
        data.setFloat64(0, value); // for accessing IEEE-754 exponent bits
        var bits = (data.getUint32(0) >>> 20) & 0x7FF;
        if (bits === 0) {
            // make it normal by multiplying a large number
            data.setFloat64(0, value * Math.pow(2, 64));
            // access its exponent bits, and subtract the large number's exponent
            bits = ((data.getUint32(0) >>> 20) & 0x7FF) - 64;
        }
        var exponent = bits - 1022; // apply bias
        // mantissa = this.ldexp(value, -exponent)  // not needed
        return exponent;
    };
    ;
    ;
    /**
     * Decode plaintext and return result
     * @function
     * @returns {Number}
     * */
    EncodedNumber.prototype.decode = function () {
        var mantissa;
        if (this.encoding.compareTo(this.public_key.n) >= 0) {
            throw "Attempted to decode corrupted number";
        }
        if (this.encoding.compareTo(this.public_key.max_int) <= 0) {
            // Positive
            mantissa = this.encoding;
        }
        else {
            if (this.encoding.compareTo(this.public_key.n.subtract(this.public_key.max_int)) >= 0) {
                // negative
                mantissa = this.encoding.subtract(this.public_key.n);
            }
            else {
                throw "OverflowError";
            }
        }
        // TODO adapt for Floating Point...
        var decodedBN = mantissa.multiply(EncodedNumber.BASE_BN.pow(this.exponent));
        return parseInt(decodedBN.toString(16), 16);
    };
    ;
    /**
     * Return an EncodedNumber with the same value
     * but a lower exponent.
     *
     * We can multiple the encoded value by BASE
     * and decrement the exponent by one without changing the
     * value. Thus we can arbitrarily ratchet down the exponent
     * of an EncodedNumber. We only run into trouble when the
     * encoded integer overflows - which we may not be able to
     * detect and warn about.
     *
     * This is necessary when adding EncodedNumbers, and can
     * be useful to hide information about the precision of
     * numbers - e.g. a protocol can fix the exponent of all
     * transmitted EncodedNumbers to some lower bound.
     *
     * @param {number} new_exp - The desired exponent
     * @returns {EncodedNumber} Instance with same value but desired exponent
     * @throws ValueError when trying to increase the exponent.
     */
    EncodedNumber.prototype.decrease_exponent_to = function (new_exp) {
        if (new_exp > this.exponent) {
            throw "New Exponent should be more negative that old exponent";
        }
        var factor = Math.pow(EncodedNumber.BASE, this.exponent - new_exp);
        //var new_enc: jsbn.BigInteger = this.encoding.multiply(factor);
        console.log("todo");
    };
    ;
    /**
     * Class method/constructor for EncodedNumber
     *
     * This encoding is carefully chosen so that it supports the same
     * operations as the Paillier cryptosystem.
     *
     * If *scalar* is a float, first approximate it as an int, int_rep:
     *     scalar = int_rep * (BASE ** exponent),
     * for some (typically negative) integer exponent, which can be
     * tuned using *precision* and *max_exponent*. Specifically,
     * exponent is chosen to be equal to or less than *max_exponent*,
     * and such that the number *precision* is not rounded to zero.
     *
     * Having found an integer representation for the float (or having
     * been given an int scalar), we then represent this integer as
     * a non-negative integer < PaillierPublicKey.n
     *
     * Paillier homomorphic arithemetic works modulo n. We take the
     * convention that a number x < n/3 is positive, and that a
     * number x > 2n/3 is negative. The range n/3 < x < 2n/3 allows
     * for overflow detection.
     *
     * @param {PublicKey} public_key
     * @param {number} scalar
     * @param {float} [precision]
     * @param {number} [max_exponent]
     *
     * @returns {EncodedNumber}
     */
    EncodedNumber.encode = function (public_key, scalar, precision, max_exponent) {
        var exponent, prec_exponent = 0;
        var scalarIsFloat = false;
        // Calculate the maximum exponent for desired precision
        if (typeof precision === "undefined") {
            var isFloat = function (n) { return n === +n && n !== (n | 0); };
            if (isFloat(scalar)) {
                // Encode with *at least* as much precision as the javascript float
                // What's the base-2 exponent on the float?
                var bin_flt_exponent = this.frexp_exponent(scalar);
                // What's the base-2 exponent of the least significant bit?
                // The least significant bit has value 2 ** bin_lsb_exponent
                var bin_lsb_exponent = bin_flt_exponent - EncodedNumber.FLOAT_MANTISSA_BITS;
                // What's the corresponding base BASE exponent? Round that down.
                prec_exponent = Math.floor(bin_lsb_exponent / EncodedNumber.LOG2_BASE);
                scalarIsFloat = true;
            }
        }
        else {
            prec_exponent = Math.floor(this.log(precision, this.BASE));
        }
        /* Remember exponents are negative for numbers < 1, but
         * positive for positive integers (and floats).
         * If we're going to store numbers with a more negative
         * exponent than demanded by the precision, then we may
         * as well bump up the actual precision.
         **/
        if (typeof max_exponent === "undefined") {
            exponent = prec_exponent;
        }
        else {
            exponent = Math.min(max_exponent, prec_exponent);
        }
        // Base ^ (-exponent) is often a tiny fraction so can't be
        // represented using the Big Integer library
        // exponent MUST be an integer though
        var multiplicand = Math.pow(this.BASE, -exponent);
        // TODO sort this out to deal with floats, strings and javascript numbers
        //if(!scalarIsFloat){
        // Use integer math
        //    var scalarStr = (new bn(scalar.toString(10), 10)).multiply(new bn(multiplicand.toString(16), 16)).toString(16);
        //} else {
        // This throws away a LOT of precision
        var scalarStr = (parseFloat(scalar.toString(10)) * multiplicand).toString(16);
        //}
        var decimalIdx = scalarStr.indexOf(".");
        if (decimalIdx > 0) {
            // Round the number
            scalarStr = scalarStr.slice(0, decimalIdx);
        }
        var int_rep = new bn(scalarStr, 16);
        // NOTE: Large javascript integers are floats...
        //var int_rep = new bn(scaledScalarStr, 16);
        if (int_rep.abs().compareTo(public_key.max_int) >= 0) {
            console.log('Scalar is too large for encoding with this public key');
            console.log(int_rep.toString(16));
            console.log(public_key.max_int.toString(16));
            throw "ValueError"; //, "Integer needs to be within +/- " + public_key.max_int;
        }
        // Wrap negative numbers by adding n
        return new EncodedNumber(public_key, int_rep.mod(public_key.n), exponent);
    };
    ;
    /**
     * Base to use when exponentiating. Larger `BASE` means
     * that exponent leaks less information. If you vary this,
     * you'll have to manually inform anyone decoding your numbers.
     */
    EncodedNumber.BASE = 16;
    // http://blog.chewxy.com/2014/02/24/what-every-javascript-developer-should-know-about-floating-point-numbers/
    EncodedNumber.FLOAT_MANTISSA_BITS = 53;
    EncodedNumber.LOG2_BASE = EncodedNumber.log(16, 2);
    // Save a reference to the base as a BigInteger
    EncodedNumber.BASE_BN = new bn(EncodedNumber.BASE.toString(), 10);
    return EncodedNumber;
})();
exports.EncodedNumber = EncodedNumber;
;
/**
 * Represents the Paillier encryption of a float or int.
 * Typically, an `EncryptedNumber` is created by {@link PublicKey.encrypt}.
 * You would only instantiate an EncryptedNumber manually if you are de-serializing
 * a number someone else encrypted.
 *
 * @namespace EncryptedNumber
 * @constructs EncryptedNumber
 *
 * @param {PublicKey} public_key - The PublicKey against which the number was encrypted.
 * @param {BigInteger} ciphertext - Encrypted representation of the encoded number.
 * @param {number} [exponent=0] - Used by {@link EncodedNumber} to keep track of fixed precision - usually negative.
 *
 * @returns {EncryptedNumber}
 */
var EncryptedNumber = (function () {
    function EncryptedNumber(public_key, ciphertext, exponent) {
    }
    /**
     * Get the raw ciphertext underlying this EncryptedNumber
     *
     * Choosing a random number is slow. Therefore, methods like
     * add and multiply take a shortcut and do not
     * follow Paillier encryption fully - every encrypted sum or
     * product should be multiplied by r ^ PublicKey.n for random r < n (i.e., the result
     * is obfuscated). Not obfuscating provides a big speed up in,
     * e.g., an encrypted dot product: each of the product terms need
     * not be obfuscated, since only the final sum is shared with
     * others - only this final sum needs to be obfuscated.
     * Not obfuscating is OK for internal use, where you are happy for
     * your own computer to know the scalars you've been adding and
     * multiplying to the original ciphertext. But this is *not* OK if
     * you're going to be sharing the new ciphertext with anyone else.
     * So, by default, this method returns an obfuscated ciphertext -
     * obfuscating it if necessary. If instead you set be_secure=False
     * then the ciphertext will be returned, regardless of whether it
     * has already been obfuscated. We thought that this approach,
     * while a little awkward, yields a safe default while preserving
     * the option for high performance.
     *
     * @param {boolean} [be_secure=true] If any untrusted party will see the returned ciphertext, then this
     *      should be true.
     * @returns {BigInteger} The ciphertext. WARNING, if be_secure is false then it could be possible
     *      for an attacker to deduce numbers involved in calculating this ciphertext.
     */
    EncryptedNumber.prototype.ciphertext = function (be_secure) {
        return "TODO";
    };
    return EncryptedNumber;
})();
exports.EncryptedNumber = EncryptedNumber;
;
