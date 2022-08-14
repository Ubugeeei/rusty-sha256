# The SHA256 hash algorithm.
## links
[spec](https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf)  | [6.2](https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf#page=23)

## Usage
```rs
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
```