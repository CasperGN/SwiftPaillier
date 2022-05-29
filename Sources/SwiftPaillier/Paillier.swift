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

    public func decrypt(publicKey: PublicKey, privateKey: PrivateKey, ciphertext: BigUInt) -> BigUInt {
        let (cp, cq) = Paillier.crt_decompose(x: ciphertext, m1: privateKey.pp, m2: privateKey.qq)
        
        // Process for p
        // TODO: dp returns 0 which breaks further processing
        let dp = cp.power(privateKey.pminusone, modulus: privateKey.pp)
        let lp = Paillier.l(u: dp, n: privateKey.p)
        let mp = (lp * privateKey.hp) % privateKey.p
        
        //process for q
        // TODO: dq returns 0 which breaks further processing
        let dq = cq.power(privateKey.qminusone, modulus: privateKey.qq)
        let lq = Paillier.l(u: dq, n:privateKey.q)
        let mq = (lq * privateKey.hq) % privateKey.q
        
        let m = Paillier.crt_recombine(x1: mp, x2: mq, m1: privateKey.p, m2: privateKey.q, m1inv: privateKey.pinv)
        
        return m
    }

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
        let dp: BigUInt
        let dq: BigUInt
        let ppinv: BigUInt
        let hp: BigUInt
        let hq: BigUInt
        let pinv: BigUInt

        init(p: BigUInt, q: BigUInt) {
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
            (dp, dq) = Paillier.crt_decompose(x: dn, m1: pminusone, m2: qminusone)
            pinv = p.inverse(q)!
            ppinv = pp.inverse(qq)!
            hp = Paillier.h(p: p, pp: pp, n:n)
            hq = Paillier.h(p: q, pp: qq, n:n)
        }
    }

    static func h(p: BigUInt, pp: BigUInt, n: BigUInt) -> BigUInt {
        let gp = BigUInt.init(nnmod((Bignum.init("1") - Bignum.init(n.description)), Bignum.init(pp.description)).description)!
        let lp = Paillier.l(u: gp, n: p)
        let hp = lp.inverse(p)!
        return hp
    }
    
    static func l(u: BigUInt, n: BigUInt) -> BigUInt {
        return (u - 1) / n
    }

    static func crt_decompose(x: BigUInt, m1: BigUInt, m2: BigUInt) -> (BigUInt, BigUInt) {
        return (x % m1, x % m2)
    }
    
    static func crt_recombine(x1: BigUInt, x2: BigUInt, m1: BigUInt, m2: BigUInt, m1inv: BigUInt) -> BigUInt {
        var diff = (x2 - x1) % m2
        if diff < 0 {
            diff += m2
        }
        let u = (diff * m1inv) % m2
        let x = x1 + (u * m1)
        return x
    }
    
    static func generateKeyPair(_ strength: Int = Paillier.defaultKeysize) -> KeyPair {
        var p, q: BigUInt
        p = SamplePrime(bitsize: strength)
        repeat {
            q = SamplePrime(bitsize: strength)
        } while p == q

        if q < p {
            swap(&p, &q)
        }

        let n = p*q
        let nn = n * n

        let privateKey = PrivateKey(p: p, q: q)
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
    
    private func encrypt(_ plaintext: BigUInt) {
        _ciphertext = rawEncrypt(plaintext)
        isBlinded = false
    }

    private func rawEncrypt(_ plaintext: BigUInt) -> BigUInt {
        let r = Randomness(ek: publicKey)
        let rn = ((r * r) * publicKey.n) % publicKey.nn
        let gm = BigUInt(plaintext * publicKey.n + 1) % publicKey.nn
        let c = (gm * rn) % publicKey.nn
        
        return BigUInt(c)

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
