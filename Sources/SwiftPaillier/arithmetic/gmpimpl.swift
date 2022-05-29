//
//  File.swift
//  
//
//  Created by Casper Nielsen on 29/05/2022.
//

import Foundation
import CGMP
import BigInt

// This function is derived from https://github.com/CasperGN/rust-paillier/blob/master/src/arithimpl/gmpimpl.rs#L20-L26
public func sample(bitsize: Int) -> BigUInt {
    let bytes = (bitsize - 1) / 8 + 1
    var buf: Array<Int> = []
    for _ in 0...bytes {
        buf.append(Int.random(in: 1..<10) >> (bytes * 8 - bitsize))
    }
    
    return BigUInt(buf.reduce(0, {BigUInt($0) * 10 + BigUInt($1)}))
}

public func SampleBelow(n: BigUInt) -> BigUInt {
    let bits = n.bitWidth
            
    while true {
        let m = sample(bitsize: bits)
        if m < n {
            return BigUInt(n)
        }
    }
}

public func Randomness(ek: Paillier.PublicKey) -> BigUInt {
    SampleBelow(n: ek.n)
}

