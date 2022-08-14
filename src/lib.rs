//! The SHA256 hash algorithm.
//! spec: https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf
//! 6.2 https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=23

#![allow(dead_code)]

#[derive(Copy, Clone)]
pub struct SHA256;
impl SHA256 {
    /*
     *
     * constant
     *
     */
    const BLOCK_SIZE: usize = 64;
    const DELIMITER: u32 = 0x80;

    /// 4bytes after the decimal point of the cube root of 64 prime numbers from smallest to largest
    /// https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=15
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xD6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    /// 4bytes after the decimal point of the square root of 8 prime numbers from smallest to largest
    /// 5.3.2  https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=18
    const H: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    /*
     *
     * constructor
     *
     */
    pub fn new() -> Self {
        SHA256
    }

    /*
     *
     * get hashed string
     *
     */
    pub fn exec(self, message: String) -> String {
        // convert message to hasher input
        let bytes = message.into_bytes();
        let padded = self.add_padding(bytes);
        let blocks = self.into_512bit_blocks(padded);

        // hash
        let hashed = self.hash(blocks);

        // convert hashed bytes to joined hex string
        hashed
            .iter()
            .map(|n| format!("{:x}", n))
            .collect::<Vec<String>>()
            .join("")
    }

    /// calculate the hash of the message
    /// https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=24
    pub fn hash(self, blocks: Vec<[u32; 16]>) -> [u32; 8] {
        let mut state = SHA256::H.clone();

        for block in blocks {
            let w = {
                let mut w = [0; SHA256::BLOCK_SIZE];

                for t in 0..SHA256::BLOCK_SIZE / 4 {
                    w[t] = block[t];
                }

                for t in (SHA256::BLOCK_SIZE / 4)..SHA256::BLOCK_SIZE {
                    w[t] = self
                        .sigma1(w[t - 2])
                        .wrapping_add(w[t - 7])
                        .wrapping_add(self.sigma0(w[t - 15]))
                        .wrapping_add(w[t - 16]);
                }

                w
            };

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
                state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
            );

            for t in 0..SHA256::BLOCK_SIZE {
                let t1 = h
                    .wrapping_add(self.SIGMA1(e))
                    .wrapping_add(self.ch(e, f, g))
                    .wrapping_add(SHA256::K[t])
                    .wrapping_add(w[t]);

                let t2 = self.SIGMA0(a).wrapping_add(self.maj(a, b, c));

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            state = [
                a.wrapping_add(state[0]),
                b.wrapping_add(state[1]),
                c.wrapping_add(state[2]),
                d.wrapping_add(state[3]),
                e.wrapping_add(state[4]),
                f.wrapping_add(state[5]),
                g.wrapping_add(state[6]),
                h.wrapping_add(state[7]),
            ];
        }

        state
    }

    /// pre-prpcess
    /// Parse the padded message into N 512-bit message blocks
    /// https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=23
    fn into_512bit_blocks(self, padded: Vec<u8>) -> Vec<[u32; 16]> {
        let mut blocks = Vec::with_capacity(padded.len() / 512);
        let mut idx = 0;
        let mut shift = 32;
        let mut block = [0; 16];
        for byte in padded.iter() {
            shift -= 8;
            block[idx] |= (*byte as u32) << shift;
            if shift == 0 {
                idx += 1;
                shift = 32;
            }
            if idx == 16 {
                blocks.push(block);
                block = [0; 16];
                idx = 0;
            }
        }
        blocks
    }

    /// pre-prpcess
    /// add padding and sizes to the message
    /// 5. https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=17
    pub fn add_padding(self, message: Vec<u8>) -> Vec<u8> {
        const SIZE_BYTES: usize = 8;

        let len = message.len();

        let mut tmp: Vec<u8> = vec![0x00; SHA256::BLOCK_SIZE];
        tmp[0] = SHA256::DELIMITER as u8;

        // add padding
        let mut padded = message.clone();
        padded = if len % SHA256::BLOCK_SIZE < SHA256::BLOCK_SIZE - SIZE_BYTES {
            vec![
                padded,
                tmp[0..(SHA256::BLOCK_SIZE - SIZE_BYTES - len % SHA256::BLOCK_SIZE)].to_vec(),
            ]
            .concat()
        } else {
            vec![
                padded,
                tmp[0..(SHA256::BLOCK_SIZE + SHA256::BLOCK_SIZE
                    - SIZE_BYTES
                    - len % SHA256::BLOCK_SIZE)]
                    .to_vec(),
            ]
            .concat()
        };

        // add length
        let len_bits = (len * 8) as u64;
        let mut size = vec![0x00; 8];
        size[4] = (len_bits >> 24) as u8;
        size[5] = (len_bits >> 16) as u8;
        size[6] = (len_bits >> 8) as u8;
        size[7] = (len_bits >> 0) as u8;

        vec![padded, size].concat()
    }

    /*
     *
     * bit opes funuctions
     *
     * https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=14
     *
     */

    /// 4.2 https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=14
    fn ch(self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }
    /// 4.3 https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=14
    fn maj(self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    /// 4.4 https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=14
    #[allow(non_snake_case)]
    fn SIGMA0(self, x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }
    /// 4.5 https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=14
    #[allow(non_snake_case)]
    fn SIGMA1(self, x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }
    /// 4.6 https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=14
    fn sigma0(self, x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }
    /// 4.7 https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=14
    fn sigma1(self, x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_padding() {
        {
            let hasher = SHA256::new();
            let pdd = hasher.add_padding(vec![]);
            assert_eq!(pdd.len(), 64);
            assert_eq!(
                pdd,
                vec![
                    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            );
        }
        {
            let hasher = SHA256::new();
            let pdd = hasher.add_padding(vec![1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(pdd.len(), 64);
            assert_eq!(
                pdd,
                vec![
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
                ]
            );
        }
    }

    #[test]
    fn test_into_512bit_blocks() {
        {
            let hasher = SHA256::new();
            assert_eq!(
                hasher.into_512bit_blocks(vec![
                    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]),
                vec![[
                    0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                    0x00000000, 0x00000000, 0x00000000, 0x00000000
                ]]
            );
        }
        {
            let hasher = SHA256::new();
            assert_eq!(
                hasher.into_512bit_blocks(vec![
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
                ]),
                vec![[
                    0x01020304, 0x05060708, 0x80000000, 0x00000000, 0x00000000, 0x00000000,
                    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                    0x00000000, 0x00000000, 0x00000000, 0x00000040
                ]]
            );
        }
    }

    #[test]
    fn test_sha256_exec() {
        let hasher = SHA256::new();

        assert_eq!(
            hasher.exec(String::from("hello")),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(
            hasher.exec(String::from("hello world")),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(
            hasher.exec(String::from("あいうえお")),
            "fdb481ea956fdb654afcc327cff9b626966b2abdabc3f3e6dbcb1667a888ed9a"
        );
    }
}
