use core::hash::Hasher;
use core::convert::TryInto;


// Nothing special, digits of pi.
const SEED1: u64 = 0x243f6a8885a308d3;
const SEED2: u64 = 0x13198a2e03707344;
const SEED3: u64 = 0xa4093822299f31d0;
const SEED4: u64 = 0x082efa98ec4e6c89;
const PREVENT_TRIVIAL_ZERO_COLLAPSE: u64 = 0x452821e638d01377;


#[inline]
fn multiply_mix(x: u64, y: u64) -> u64 {
    // We compute the full u64 x u64 -> u128 product, this is a single mul
    // instruction on x86-64, one mul and one mulhi on ARM64.
    let full = (x as u128) * (y as u128);
    let lo = full as u64;
    let hi = (full >> 64) as u64;
    
    // The middle bits of the full product fluctuate the most with small changes
    // in the input. This is the top bits of lo and the bottom bits of hi. We
    // can thus make the entire output fluctuate with small changes to the input
    // by XOR'ing these two halves.
    lo ^ hi

    // Unfortunately both 2^64 + 1 and 2^64 - 1 have small prime factors,
    // otherwise combining with + or - could result in a really strong hash, as:
    //     x * y = 2^64 * hi + lo = (-1) * hi + lo = lo - hi,   (mod 2^64 + 1)
    //     x * y = 2^64 * hi + lo =    1 * hi + lo = lo + hi,   (mod 2^64 - 1)
    // Multiplicative hashing is universal in a field (like mod p).
}


/// A wyhash-inspired non-collision-resistant hash for strings/slices, with a
/// focus on small strings and small codesize.
#[inline]
fn hash_bytes(mut bytes: &[u8]) -> u64 {
    let len = bytes.len();
    let mut s0 = SEED1;
    let mut s1 = SEED2;
    if len <= 16 {
        if len >= 8 {
            s0 ^= u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            s1 ^= u64::from_le_bytes(bytes[len-8..].try_into().unwrap());
        } else if len >= 4 {
            s0 ^= u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as u64;
            s1 ^= u32::from_le_bytes(bytes[len-4..].try_into().unwrap()) as u64;
        } else if len > 0 {
            let lo = bytes[0];
            let mid = bytes[len / 2];
            let hi = bytes[len - 1];
            s0 ^= lo as u64;
            s1 ^= ((hi as u64) << 8) | mid as u64;
        }
    } else {
        // Handle bulk (can partially overlap with suffix).
        let mut off = 0;
        while off < len - 16 {
            let x = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            let y = u64::from_le_bytes(bytes[off + 8..off + 16].try_into().unwrap());
            
            // Replace s1 with a mix of s0, x, and y, and s0 with s1.
            // This ensures the compiler can unroll this loop into two
            // independent streams, one operating on s0, the other on s1.
            // 
            // Since zeroes are a common input we prevent an immediate trivial
            // collapse of the hash function by XOR'ing a constant with y.
            let t = multiply_mix(s0 ^ x, PREVENT_TRIVIAL_ZERO_COLLAPSE ^ y);
            s0 = s1;
            s1 = t;
            off += 16;
        }
    
        let suffix = &bytes[len - 16..];
        s0 ^= u64::from_le_bytes(suffix[0..8].try_into().unwrap());
        s1 ^= u64::from_le_bytes(suffix[8..16].try_into().unwrap());
    }

    multiply_mix(s0, s1) ^ len as u64
}


/// Fast non-collision-resistant hash.
pub struct MultilinearHasher {
    hash: u64,
    rng_a: u64,
    rng_b: u64,
}

impl Default for MultilinearHasher {
    #[inline]
    fn default() -> Self {
        Self { hash: 0, rng_a: SEED3, rng_b: SEED4 }
    }
}

impl MultilinearHasher {
    #[inline]
    pub fn with_seed(seed: usize) -> Self {
        Self { hash: 0, rng_a: seed as u64 ^ SEED3, rng_b: seed as u64 ^ SEED4 }
    }

    #[inline]
    fn gen_rng(&mut self) -> u64 {
        // A very mediocre RNG, but it is important that it is non-linear,
        // otherwise we collapse to a sum hash.
        self.rng_b = self.rng_b.wrapping_add(self.rng_a);
        self.rng_a ^= self.rng_b.rotate_right(27);
        self.rng_a
    }

    #[inline]
    fn add_to_hash(&mut self, x: u64) {
        // Mix x with our random stream and add into our accumulator.
        let h = x.wrapping_mul(self.gen_rng() | 1);
        self.hash = self.hash.wrapping_add(h);
    }
}

impl Hasher for MultilinearHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.add_to_hash(hash_bytes(bytes))
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add_to_hash(i as u64);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add_to_hash(i as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add_to_hash(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add_to_hash(i as u64);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add_to_hash(i as u64);
    }

    #[inline]
    fn write_length_prefix(&mut self, len: usize) {
        // Most cases will specialize hash_slice anyway which calls write,
        // which encodes the length already.
    }
    
    #[inline]
    fn write_str(&mut self, s: &str) {
        // We don't need anything special here.
        self.write(s.as_bytes())
    }
    
    #[inline]
    fn finish(&self) -> u64 {
        self.hash as u64
    }
}
