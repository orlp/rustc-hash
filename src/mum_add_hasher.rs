use core::hash::Hasher;
use core::convert::TryInto;

// There is absolutely nothing special about these numbers, they are just random
// bits so our hash can have an additive structure without leading to trivial
// swap collisions. If we did this:
//    h = mix(m[0]) + mix(m[1]) + ...
// you have a trivial collision between (a, b) and (b, a). But the following
// structure using random key k is immune to this:
//    h = mix(combine(m[0], k[0])) + mix(combine(m[0], k[0])) + ...
// An additive structure means we can use instruction-level parallelism, instead
// of having a long dependency chain. The additive structure is inspired by
// universal hashing theory, even though we will not use a universal mix().
// 
// To truly prove there is nothing special about these numbers, these are the
// fractional hexidecimal digits of pi, 0x243f6a8885a308d3 / 2^64 = 0.141592...
const ENTROPY: [u64; 16] = [
    0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
    0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
    0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
    0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69,
];

// Further pi digits, used for the string hash.
const SEED1: u64 = 0xa458fea3f4933d7e;
const SEED2: u64 = 0x0d95748f728eb658;
const PREVENT_TRIVIAL_ZERO_COLLAPSE: u64 = 0x718bcd5882154aee;


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
#[derive(Default, Clone)]
pub struct MumAddHasher {
    hash: u64,
    rng: u64,
    entropy_idx: usize,
}

impl MumAddHasher {
    #[inline]
    pub fn with_seed(seed: usize) -> Self {
        Self { hash: seed as u64, rng: seed as u64, entropy_idx: 0 }
    }

    #[inline]
    fn gen_rng(&mut self) -> u64 {
        // Simulate a proper RNG at top speed by simply adding from a buffer of
        // entropy. When the entropy runs out we wrap around, so our 'RNG' is
        // rather predictable after that point: our RNG at iteration i will have
        // value a + sum(ENTROPY) * (i / 16) for some a dependent on i % 16.
        // 
        // However, most hashes never exhaust ENTROPY, and if they do the small
        // differences are avalanched by multiply_mix, so there is no reason to
        // believe this is an issue if the data is not specifically engineered
        // to attack the hash from this angle.
        // 
        // Finally, if you are deriving Hash on a struct this all gets optimized
        // out to a compile-time constant.
        self.entropy_idx %= 16;
        self.rng = self.rng.wrapping_add(ENTROPY[self.entropy_idx]);
        self.entropy_idx += 1;
        self.rng
    }

    #[inline]
    fn add_to_hash(&mut self, x: u64) {
        // Mix x with our random stream and add into our accumulator.
        let h = multiply_mix(x, self.gen_rng());
        self.hash = self.hash.wrapping_add(h);
    }

    #[inline]
    fn double_add_to_hash(&mut self, x: u64, y: u64) {
        // Mix x and y with our random stream and add into our accumulator.
        let h = multiply_mix(x ^ self.gen_rng(), y ^ self.gen_rng());
        self.hash = self.hash.wrapping_add(h);
    }
}

impl Hasher for MumAddHasher {
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
    fn write_u128(&mut self, i: u128) {
        self.double_add_to_hash(i as u64, (i >> 64) as u64);
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