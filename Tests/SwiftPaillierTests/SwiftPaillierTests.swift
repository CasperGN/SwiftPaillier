import XCTest
import BigInt
@testable import SwiftPaillier

final class SwiftPaillierTests: XCTestCase {
    func testSimpleOperations() {
        let paillier = Paillier()
    
        let (ek, dk) = paillier.generateKeys(strength: 2048)
        
        let randomInt = BigUInt(12345678)
        let encryption = paillier.encrypt(randomInt, publicKey: ek)
    
        let plaintext = paillier.decrypt(publicKey: ek, privateKey: dk, ciphertext: encryption.ciphertext)
        
        assert(plaintext == randomInt)
    }

    static var allTests = [
        ("testSimpleOperations", testSimpleOperations),
    ]
}
