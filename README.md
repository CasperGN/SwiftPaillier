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

## License

This package is licensed under the MIT license. By default it uses [GMP](https://gmplib.org/), which is licensed under [GNU LGPLv3](https://www.gnu.org/licenses/lgpl-3.0.de.html), and [BigInt](https://github.com/attaswift/BigInt), which is MIT licensed.

Since GMP is dynamically linked, this conforms to the GNU LGPLv3, but pay attention to the conditions of the LGPLv3 when using this library.

(It is possible to use SwiftPaillier without GMP and only use BigInt, which is slower.)
