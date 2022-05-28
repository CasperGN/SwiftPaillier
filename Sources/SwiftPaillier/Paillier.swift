//
//  Paillier.swift
//  Created by Simon Kempendorf on 07.02.19.
//

import Foundation
import BigInt
import Bignum

public final class Paillier {
    public static let defaultKeysize = 2048

    public var privateKey: PrivateKey
    public var publicKey: PublicKey
    
    let jsonEncoder = JSONEncoder()
    
    public init(strength: Int = Paillier.defaultKeysize) {
        let keyPair = Paillier.generateKeyPair(strength)
        privateKey = keyPair.privateKey
        publicKey = keyPair.publicKey
    }

    public init(keyPair: KeyPair) {
        self.privateKey = keyPair.privateKey
        self.publicKey = keyPair.publicKey
    }
    
    public func generateKeys(strength: Int = Paillier.defaultKeysize) -> (PublicKey, PrivateKey) {
        let keyPair = Paillier.generateKeyPair(strength)
        privateKey = keyPair.privateKey
        publicKey = keyPair.publicKey
        
        return (publicKey, privateKey)
    }

    public func L(x: BigUInt, p: BigUInt) -> BigUInt {
        return (x-1)/p
    }

    public func L(x: Bignum, p: Bignum) -> Bignum {
        return (x-1)/p
    }

    /*public func decrypt(publicKey: PublicKey, privateKey: PrivateKey, ciphertext: BigUInt, type: DecryptionType = .bigIntDefault) -> BigUInt {
        switch type {
        case .bigIntFast:
            let mp = (L(x: ciphertext.power(privateKey.p - 1, modulus: privateKey.psq), p: privateKey.p) * privateKey.hp) % privateKey.p
            let mq = (L(x: ciphertext.power(privateKey.q - 1, modulus: privateKey.qsq), p: privateKey.q) * privateKey.hq) % privateKey.q

            // Solve using Chinese Remainder Theorem
            let u = (mq-mp) * privateKey.pinv
            return mp + ((u % privateKey.q) * privateKey.p)
        case .bigIntDefault:
            let lambda = (privateKey.p-1)*(privateKey.q-1)
            let mu = L(x: publicKey.g.power(lambda.magnitude, modulus: publicKey.nsq), p: publicKey.n).inverse(publicKey.n)!
            return (L(x: ciphertext.power(lambda, modulus: publicKey.nsq), p: publicKey.n) * mu) % publicKey.n
        case .bigNumFast:
            let ciphertext = Bignum(ciphertext.description)
            let mp = (L(x: mod_exp(ciphertext, privateKey.pnum - 1, privateKey.psqnum), p: privateKey.pnum) * privateKey.hpnum) % privateKey.pnum
            let mq = (L(x: mod_exp(ciphertext, privateKey.qnum - 1, privateKey.qsqnum), p: privateKey.qnum) * privateKey.hqnum) % privateKey.qnum

            // Solve using Chinese Remainder Theorem
            let u = (mq-mp) * privateKey.pinvnum
            return BigUInt((mp + ((u % privateKey.qnum) * privateKey.pnum)).string())!
        case .bigNumDefault:
            let ciphertext = Bignum(ciphertext.description)
            let lambda = (privateKey.pnum-1)*(privateKey.qnum-1)
            let mu = inverse(L(x: mod_exp(publicKey.gnum, lambda, publicKey.nsqnum), p: publicKey.nnum), publicKey.nnum)!
            return BigUInt(((L(x: mod_exp(ciphertext, lambda, publicKey.nsqnum), p: publicKey.nnum) * mu) % publicKey.nnum).string())!
        }
    }*/

    public func encrypt(_ plaintext: BigUInt, publicKey: PublicKey) -> PaillierEncryption {
        return PaillierEncryption(plaintext, for: publicKey)
    }

    public enum DecryptionType {
        case bigIntDefault
        case bigIntFast
        case bigNumDefault
        case bigNumFast
    }
}

// MARK: Keys and their handling
public extension Paillier {
    struct KeyPair {
        public let privateKey: PrivateKey
        public let publicKey: PublicKey
    }

    struct PublicKey: Codable {
        let n: BigUInt
        let nn: BigUInt

        init(n: BigUInt, nn: BigUInt) {
            self.n = n
            self.nn = nn
        }
    }

    struct PrivateKey: Codable {
        let p: BigUInt
        let q: BigUInt

        // MARK: Precomputed values
        let pp: BigUInt
        let qq: BigUInt
        let n: BigUInt
        let nn: BigUInt
        let pminusone: BigUInt
        let qminusone: BigUInt
        let phi: BigUInt
        let dn: BigUInt
        let pinv: BigUInt
        let ppinv: BigUInt
        let hp: BigUInt
        let hq: BigUInt

        init(   p: BigUInt, q: BigUInt, g: BigUInt) {
            self.p = p
            self.q = q
            pp = p.power(2)
            qq = q.power(2)
            n = p * q
            nn = n * n
            pminusone = p - 1
            qminusone = q - 1
            phi = pminusone * qminusone
            dn = n.inverse(phi)!
            pinv = p.inverse(q)!
            ppinv = pp.inverse(qq)!
            hp = Paillier.h(on: g, p: p, pp: pp)
            hq = Paillier.h(on: g, p: q, pp: qq)
        }
    }

    static func h(on g: BigUInt, p: BigUInt, pp: BigUInt) -> BigUInt {
        let parameter = g.power((p - 1), modulus: pp)
        let lOfParameter = (parameter-1)/p
        return lOfParameter.inverse(p)!
    }

    static func generatePrime(_ width: Int) -> BigUInt {
        while true {
            var random = BigUInt.randomInteger(withExactWidth: width)
            random |= BigUInt(1)
            if Bignum(random.description).isPrime(rounds: 30) {
                return random
            }
        }
    }

    static func generateKeyPair(_ strength: Int = Paillier.defaultKeysize) -> KeyPair {
        var p, q: BigUInt
        p = generatePrime(strength/2)
        repeat {
            q = generatePrime(strength/2)
        } while p == q

        if q < p {
            swap(&p, &q)
        }

        let n = p*q
        let nn = n * n

        let privateKey = PrivateKey(p: p, q: q, g: n)
        let publicKey = PublicKey(n: n, nn: nn)
        return KeyPair(privateKey: privateKey, publicKey: publicKey)
    }
}

public class PaillierEncryption: Encodable {
    private var _ciphertext: BigUInt
    public var ciphertext: BigUInt {
        get {
            /*if !isBlinded {
                blind()
            }*/
            return _ciphertext
        }
    }
    private var isBlinded: Bool
    public let publicKey: Paillier.PublicKey

    public init(_ plaintext: BigUInt, for publicKey: Paillier.PublicKey) {
        self.publicKey = publicKey
        self._ciphertext = BigUInt(0)
        self.isBlinded = false
        encrypt(plaintext)
    }

    public init(ciphertext: BigUInt, for publicKey: Paillier.PublicKey) {
        self.publicKey = publicKey
        self._ciphertext = ciphertext
        isBlinded = false
    }
    
    // This function is derived from https://github.com/CasperGN/rust-paillier/blob/master/src/arithimpl/gmpimpl.rs#L20-L26
    private func sample(bitsize: Int) -> BigUInt {
        let bytes = (bitsize - 1) / 8 + 1
        var buf: Array<Int> = []
        for _ in 0...bytes {
            buf.append(Int.random(in: 1..<10) >> (bytes * 8 - bitsize))
        }
        
        return BigUInt(buf.reduce(0, {BigUInt($0) * 10 + BigUInt($1)}))
    }
    
    private func SampleBelow(n: BigUInt) -> BigUInt {
        let bits = n.bitWidth
                
        while true {
            let m = sample(bitsize: bits)
            if m < n {
                return BigUInt(n)
            }
        }
    }

    private func Randomness(ek: Paillier.PublicKey) -> BigUInt {
        SampleBelow(n: ek.n)
    }
    
    private func encrypt(_ plaintext: BigUInt) {
        //let plaintextnum = BigUInt(plaintext.description)
        _ciphertext = rawEncrypt(plaintext)
        isBlinded = false
    }

    private func rawEncrypt(_ plaintext: BigUInt) -> BigUInt {
        
        let r = Randomness(ek: publicKey)
        let rn = r.power(publicKey.n, modulus: publicKey.nn)
        let gm = BigUInt(plaintext * publicKey.n + 1) % publicKey.nn
        let c = (gm * rn) % publicKey.nn
        return BigUInt(c)
        //return (plaintext * publicKey.nnum + 1) % publicKey.nsqnum

        // General (default) solution:
        // _ciphertext = publicKey.g.power(plaintext, modulus: publicKey.nsq)
    }

    /*private func rawBlind(_ ciphertext: Bignum) -> Bignum {
        let r = Bignum(BigUInt.randomInteger(lessThan: publicKey.n).description)
        let cipher = ciphertext * mod_exp(r, publicKey.nnum, publicKey.nsqnum)
        return cipher % publicKey.nsqnum
    }

    public func blind() {
        _ciphertext = rawBlind(_ciphertext)
        isBlinded = true
    }

    @discardableResult
    public func add(_ scalar: Bignum) -> PaillierEncryption {
        let ciphertext = rawEncrypt(scalar)
        add(ciphertext: ciphertext)
        return self
    }

    @discardableResult
    public func subtract(_ scalar: Bignum) -> PaillierEncryption {
        let ciphertext = rawEncrypt(scalar)
        subtract(ciphertext: ciphertext)
        return self
    }

    @discardableResult
    public func add(_ scalar: BigUInt) -> PaillierEncryption {
        let ciphertext = rawEncrypt(Bignum(scalar.description))
        add(ciphertext: ciphertext)
        return self
    }

    @discardableResult
    public func subtract(_ scalar: BigUInt) -> PaillierEncryption {
        let ciphertext = rawEncrypt(Bignum(scalar.description))
        subtract(ciphertext: ciphertext)
        return self
    }

    @discardableResult
    public func subtract(ciphertext: BigUInt) -> PaillierEncryption {
        subtract(ciphertext: Bignum(ciphertext.description))
        return self
    }

    @discardableResult
    public func add(ciphertext: BigUInt) -> PaillierEncryption {
        add(ciphertext: Bignum(ciphertext.description))
        return self
    }

    @discardableResult
    public func subtract(ciphertext: Bignum) -> PaillierEncryption {
        add(ciphertext: inverse(ciphertext, publicKey.nsqnum)!)
        return self
    }

    @discardableResult
    public func add(ciphertext: Bignum) -> PaillierEncryption {
        _ciphertext = (_ciphertext * ciphertext) % publicKey.nsqnum
        isBlinded = false
        return self
    }

    @discardableResult
    public func multiply(_ scalar: BigUInt) -> PaillierEncryption {
        multiply(Bignum(scalar.description))
        return self
    }

    @discardableResult
    public func multiply(_ scalar: Bignum) -> PaillierEncryption {
        _ciphertext = mod_exp(_ciphertext, scalar, publicKey.nsqnum)
        isBlinded = false
        return self
    }*/
}
