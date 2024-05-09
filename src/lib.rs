//! A speedy, non-cryptographic hashing algorithm used by `rustc` and Firefox.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "std")]
//! # fn main() {
//! use rustc_hash::FxHashMap;
//!
//! let mut map: FxHashMap<u32, u32> = FxHashMap::default();
//! map.insert(22, 44);
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() { }
//! ```

#![feature(hasher_prefixfree_extras)]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "rand")]
extern crate rand;

#[cfg(feature = "rand")]
mod random_state;

mod seeded_state;

use core::convert::TryInto;
use core::default::Default;
#[cfg(feature = "std")]
use core::hash::BuildHasherDefault;
use core::hash::Hasher;
use core::mem::size_of;
use core::ops::BitXor;
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

/// Type alias for a hash map that uses the Fx hashing algorithm.
#[cfg(feature = "std")]
pub type FxHashMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;

/// Type alias for a hash set that uses the Fx hashing algorithm.
#[cfg(feature = "std")]
pub type FxHashSet<V> = HashSet<V, BuildHasherDefault<FxHasher>>;

#[cfg(feature = "rand")]
pub use random_state::{FxHashMapRand, FxHashSetRand, FxRandomState};

pub use seeded_state::{FxHashMapSeed, FxHashSetSeed, FxSeededState};

mod mum_add_hasher;
pub use mum_add_hasher::MumAddHasher as FxHasher;



/*
#[cfg(test)]
mod tests {
    #[cfg(not(any(target_pointer_width = "64", target_pointer_width = "32")))]
    compile_error!("The test suite only supports 64 bit and 32 bit usize");

    use crate::FxHasher;
    use core::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher};

    macro_rules! test_hash {
        (
            $(
                hash($value:expr) == $result:expr,
            )*
        ) => {
            $(
                assert_eq!(BuildHasherDefault::<FxHasher>::default().hash_one($value), $result);
            )*
        };
    }

    const B32: bool = cfg!(target_pointer_width = "32");

    #[test]
    fn unsigned() {
        test_hash! {
            hash(0_u8) == 0,
            hash(1_u8) == if B32 { 2654435769 } else { 5871781006564002453 },
            hash(100_u8) == if B32 { 3450571844 } else { 15329034371404145204 },
            hash(u8::MAX) == if B32 { 2571255623 } else { 3117886703346944619 },

            hash(0_u16) == 0,
            hash(1_u16) == if B32 { 2654435769 } else { 5871781006564002453 },
            hash(100_u16) == if B32 { 3450571844 } else { 15329034371404145204 },
            hash(u16::MAX) == if B32 { 3682698823 } else { 8086887590654047595 },

            hash(0_u32) == 0,
            hash(1_u32) == if B32 { 2654435769 } else { 5871781006564002453 },
            hash(100_u32) == if B32 { 3450571844 } else { 15329034371404145204 },
            hash(u32::MAX) == if B32 { 1640531527 } else { 15394791018899305835 },

            hash(0_u64) == 0,
            hash(1_u64) == if B32 { 703266523 } else { 5871781006564002453 },
            hash(100_u64) == if B32 { 2407204753 } else { 15329034371404145204 },
            hash(u64::MAX) == if B32 { 1660667835 } else { 12574963067145549163 },

            hash(0_u128) == 0,
            hash(1_u128) == if B32 { 1294492036 } else { 956286968014291186 },
            hash(100_u128) == if B32 { 3411300242 } else { 2770938889503972258 },
            hash(u128::MAX) == if B32 { 3723263291 } else { 15973479568771280466 },

            hash(0_usize) == 0,
            hash(1_usize) == if B32 { 2654435769 } else { 5871781006564002453 },
            hash(100_usize) == if B32 { 3450571844 } else { 15329034371404145204 },
            hash(usize::MAX) == if B32 { 1640531527 } else { 12574963067145549163 },
        }
    }

    #[test]
    fn signed() {
        test_hash! {
            hash(i8::MIN) == if B32 { 465362048 } else { 13718205891810249344 },
            hash(0_i8) == 0,
            hash(1_i8) == if B32 { 2654435769 } else { 5871781006564002453 },
            hash(100_i8) == if B32 { 3450571844 } else { 15329034371404145204 },
            hash(i8::MAX) == if B32 { 2105893575 } else { 7846424885246246891 },

            hash(i16::MIN) == if B32 { 3168567296 } else { 6979334298609025024 },
            hash(0_i16) == 0,
            hash(1_i16) == if B32 { 2654435769 } else { 5871781006564002453 },
            hash(100_i16) == if B32 { 3450571844 } else { 15329034371404145204 },
            hash(i16::MAX) == if B32 { 514131527 } else { 1107553292045022571 },

            hash(i32::MIN) == if B32 { 2147483648 } else { 10633286012731654144 },
            hash(0_i32) == 0,
            hash(1_i32) == if B32 { 2654435769 } else { 5871781006564002453 },
            hash(100_i32) == if B32 { 3450571844 } else { 15329034371404145204 },
            hash(i32::MAX) == if B32 { 3788015175 } else { 4761505006167651691 },

            hash(i64::MIN) == if B32 { 2147483648 } else { 9223372036854775808 },
            hash(0_i64) == 0,
            hash(1_i64) == if B32 { 703266523 } else { 5871781006564002453 },
            hash(100_i64) == if B32 { 2407204753 } else { 15329034371404145204 },
            hash(i64::MAX) == if B32 { 3808151483 } else { 3351591030290773355 },

            hash(i128::MIN) == if B32 { 2147483648 } else { 9223372036854775808 },
            hash(0_i128) == 0,
            hash(1_i128) == if B32 { 1294492036 } else { 956286968014291186 },
            hash(100_i128) == if B32 { 3411300242 } else { 2770938889503972258 },
            hash(i128::MAX) == if B32 { 1575779643 } else { 6750107531916504658 },

            hash(isize::MIN) == if B32 { 2147483648 } else { 9223372036854775808 },
            hash(0_isize) == 0,
            hash(1_isize) == if B32 { 2654435769 } else { 5871781006564002453 },
            hash(100_isize) == if B32 { 3450571844 } else { 15329034371404145204 },
            hash(isize::MAX) == if B32 { 3788015175 } else { 3351591030290773355 },
        }
    }

    // Avoid relying on any `Hash` implementations in the standard library.
    struct HashBytes(&'static [u8]);
    impl Hash for HashBytes {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            state.write(self.0);
        }
    }

    #[test]
    fn bytes() {
        test_hash! {
            hash(HashBytes(&[])) == 0,
            hash(HashBytes(&[0])) == 0,
            hash(HashBytes(&[0, 0, 0, 0, 0, 0])) == 0,
            hash(HashBytes(&[1])) == if B32 { 2654435769 } else { 5871781006564002453 },
            hash(HashBytes(&[2])) == if B32 { 1013904242 } else { 11743562013128004906 },
            hash(HashBytes(b"uwu")) == if B32 { 3939043750 } else { 16622306935539548858 },
            hash(HashBytes(b"These are some bytes for testing rustc_hash.")) == if B32 { 2345708736 } else { 12390864548135261390 },
        }
    }

    #[test]
    fn with_seed_actually_different() {
        let seeds = [
            [1, 2],
            [42, 17],
            [124436707, 99237],
            [usize::MIN, usize::MAX],
        ];

        for [a_seed, b_seed] in seeds {
            let a = || FxHasher::with_seed(a_seed);
            let b = || FxHasher::with_seed(b_seed);

            for x in u8::MIN..=u8::MAX {
                let mut a = a();
                let mut b = b();

                x.hash(&mut a);
                x.hash(&mut b);

                assert_ne!(a.finish(), b.finish())
            }
        }
    }
}
*/