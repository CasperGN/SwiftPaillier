# SwiftPaillier

An implementation of Paillier's homomorphic encryption in Swift. Forked to implement the functionality needed by Helicene-inc. The current implementation seeks to align the Paillier implementation in [rust-paillier](https://github.com/mortendahl/rust-paillier).

## Installation via SPM

Declare a dependency on this package inside your `Package.swift`:
```swift
.package(url: "https://github.com/helicene-inc/SwiftPaillier.git", from: "1.0.0"),
// ...
.target(..., dependencies: [..., "SwiftPaillier"]),
```

## Usage

**NB:** Currently the decryption method does not yield the proper plaintext as supplied by input. This is currently being resolved.

```swift
import BigInt
import SwiftPaillier

let paillier = Paillier()

let (ek, dk) = paillier.generateKeys(strength: 2048)

let randomInt = BigUInt(12345678)
let encryption = paillier.encrypt(randomInt, publicKey: ek)

let plaintext = paillier.decrypt(publicKey: ek, privateKey: dk, ciphertext: encryption.ciphertext)
assert((randomInt + plaintext) == decryptedText)
```

## Implementation details, considerations and deficencies

The implementation of the `encrypt` and `decrypt` functions is based off of Section 7 - Efficiency and Implementation Aspects - in the [Public-Key Cryptosystems Based on Composite Degree Residuosity Classes by Pascal Paillier](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf) and seeks to optimize the decryption workload by utilizing the [C. Ding, D. Pei and A. Salomaa, Chinese Remainder Theorem - Applications in Computing, Coding, Cryptography, World Scientific Publishing, 1996](https://www.worldscientific.com/worldscibooks/10.1142/3254) (_NB: requires paid access_).

### Lack of arithmetic operations

The need for `Helicene-inc` does not require for the library to supply arithmetic operations and as a result of that, the arithmetic operations (subtract, addition, division and multiplication) has been removed.  
The arithmetic operations _may_ be implemented in a later release again but for now it is not implemented.

### Testing decryption


```swift
let paillier = Paillier()

let (ek, dk) = paillier.generateKeys(strength: 2048)

let randomInt = BigUInt(12345678)
let encryption = paillier.encrypt(randomInt, publicKey: ek)
    
let plaintext = paillier.decrypt(publicKey: ek, privateKey: dk, ciphertext: encryption.ciphertext)        
assert(plaintext == randomInt)
```
Yields
```
...
Test Suite 'All tests' started at 2022-06-07 20:17:53.120
Test Suite 'SwiftPaillierTests.xctest' started at 2022-06-07 20:17:53.120
Test Suite 'SwiftPaillierTests' started at 2022-06-07 20:17:53.121
Test Case '-[SwiftPaillierTests.SwiftPaillierTests testSimpleOperations]' started.
Test Case '-[SwiftPaillierTests.SwiftPaillierTests testSimpleOperations]' passed (72.621 seconds).
Test Suite 'SwiftPaillierTests' passed at 2022-06-07 20:19:05.742.
	 Executed 1 test, with 0 failures (0 unexpected) in 72.621 (72.622) seconds
Test Suite 'SwiftPaillierTests.xctest' passed at 2022-06-07 20:19:05.742.
	 Executed 1 test, with 0 failures (0 unexpected) in 72.621 (72.622) seconds
Test Suite 'All tests' passed at 2022-06-07 20:19:05.743.
	 Executed 1 test, with 0 failures (0 unexpected) in 72.621 (72.623) seconds
Program ended with exit code: 0
```

### Notes about Prime generation and verification

The current implementation to generate and verify the random Prime number _p_ as input to the `KeyGeneration` is not fully implemented to adhere to the Practical Considerations (page 260) section in Chapter 11.5 Prime Number Generation of Applied Cryptography by Bruce Schneier (ISBN13: 9781119096726).

The current implementation implements:
- [X] Generate random _n_-bit number, _p_
- [ ] Set the high-order and low-order bit to 1 (currently the low-order bit is implemented high-level by checking if _p_ is odd and if not increment by 1)
- [X] Check to make sure _p_ is not divisable by any small primes - implemented using [BoringSSL's table](https://boringssl.googlesource.com/boringssl/+/master/crypto/bn/prime.c)
- [ ] Perform Rabin-Miller test for some random a. If _p_ passes, generate another random _a_ and go through the test again

## License

This package is licensed under the MIT license. By default it uses [GMP](https://gmplib.org/), which is licensed under [GNU LGPLv3](https://www.gnu.org/licenses/lgpl-3.0.de.html), and [BigInt](https://github.com/attaswift/BigInt), which is MIT licensed.

Since GMP is dynamically linked, this conforms to the GNU LGPLv3, but pay attention to the conditions of the LGPLv3 when using this library.

(It is possible to use SwiftPaillier without GMP and only use BigInt, which is slower.)
