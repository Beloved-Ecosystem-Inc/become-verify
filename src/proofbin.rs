// SDK-free reader for SP1 6.8.1 `SP1ProofWithPublicValues` files as `.save()` writes them (bincode, little-endian,
// u64 length prefixes). Accepts exactly a Groth16 proof with no TEE proof and no trailing bytes.
pub struct ProofBin {
    pub vkey_input: String,      // public_inputs[0]: the program vkey as a decimal string
    pub onchain_bytes: Vec<u8>,  // groth16_vkey_hash[..4] ++ hex-decoded encoded_proof (= SP1ProofWithPublicValues::bytes())
    pub public_values: Vec<u8>,
    pub sp1_version: String,
    // Stored copies the Groth16 check itself does not read (it rebuilds them from the public values, the pinned key
    // and encoded_proof); check_stored() requires each to match exactly, so an edited copy can't print PASS.
    pub public_inputs: [String; 5], // [vkey, public-values digest, exit code, vk root, proof nonce] (decimal)
    pub encoded: String,            // encoded_proof as stored (hex)
    pub raw: String,                // raw_proof as stored (hex): gnark's serialization of the same proof points
    pub vk_hash: [u8; 32],          // groth16_vkey_hash: sha256 of the Groth16 verifying key
}

/// The SP1 circuit version string of the release proofs (SDK 6.8.1).
pub const CIRCUIT_VERSION: &str = "v6.1.0";
/// encoded_proof: exit code, vk root, proof nonce (32 bytes each) and the eight 32-byte Groth16 proof words.
const ENCODED_BYTES: usize = 96 + 256;
/// raw_proof tail after the 256 bytes of proof points: a zero commitment count (4 bytes) and a zero commitment
/// proof of knowledge (64 bytes); the release circuit has no commitments.
const RAW_TAIL: usize = 4 + 64;

fn hexs(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
/// A stored public input must be the canonical decimal of these 32 big-endian bytes (no sign, no leading zeros).
fn dec_is(d: &str, bytes: &[u8]) -> bool {
    (d == "0" || !d.starts_with('0')) && dec_to_hex32(d).as_deref() == Some(format!("0x{}", hexs(bytes)).as_str())
}

impl ProofBin {
    /// Every redundant copy in the file must equal what the checker rebuilds or pins. `vkey` is the pinned program key
    /// (0x + 64 hex). Purely a consistency check: the Groth16 verification is separate and unchanged.
    pub fn check_stored(&self, vkey: &str) -> Result<(), String> {
        let f = |w: &str| Err(format!("proof file: the stored {} does not match the proof (edited file?)", w));
        if self.sp1_version != CIRCUIT_VERSION { return f("circuit version"); }
        let pin = vkey.strip_prefix("0x").unwrap_or(vkey);
        if !(self.public_inputs[0] == "0" || !self.public_inputs[0].starts_with('0'))
            || dec_to_hex32(&self.public_inputs[0]).as_deref() != Some(format!("0x{}", pin).as_str()) { return f("program key (public input 0)"); }
        use sha2::{Digest, Sha256};
        let vkh: [u8; 32] = Sha256::digest(*sp1_verifier::GROTH16_VK_BYTES).into();
        if self.vk_hash != vkh { return f("Groth16 key hash"); }
        let enc = match unhex(&self.encoded) { Ok(e) => e, Err(_) => return f("encoded proof") };
        if enc.len() != ENCODED_BYTES || self.encoded != hexs(&enc) { return f("encoded proof"); }
        if !dec_is(&self.public_inputs[1], &sp1_verifier::hash_public_inputs(&self.public_values)) { return f("public-values digest (public input 1)"); }
        for (k, name) in [(2usize, "exit code (public input 2)"), (3, "vk root (public input 3)"), (4, "proof nonce (public input 4)")] {
            if !dec_is(&self.public_inputs[k], &enc[32 * (k - 2)..32 * (k - 1)]) { return f(name); }
        }
        let mut raw = enc[96..].to_vec(); raw.extend([0u8; RAW_TAIL]);
        if self.raw != hexs(&raw) { return f("raw proof"); }
        Ok(())
    }
}

struct R<'a> { b: &'a [u8], i: usize }
impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.b.len() - self.i < n { return Err("proof file is truncated".into()) }
        let s = &self.b[self.i..self.i + n]; self.i += n; Ok(s)
    }
    fn u32(&mut self) -> Result<u32, String> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn len(&mut self) -> Result<usize, String> {
        let n = u64::from_le_bytes(self.take(8)?.try_into().unwrap());
        if n > (self.b.len() - self.i) as u64 { return Err("proof file: length field larger than the file".into()) }
        Ok(n as usize)
    }
    fn bytes(&mut self) -> Result<&'a [u8], String> { let n = self.len()?; self.take(n) }
    fn string(&mut self) -> Result<String, String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| "proof file: string is not UTF-8".into())
    }
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_hexdigit()) { return Err("proof file: encoded_proof is not hex".into()) }
    Ok((0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect())
}

pub fn parse(b: &[u8]) -> Result<ProofBin, String> {
    let mut r = R { b, i: 0 };
    let tag = r.u32()?;
    if tag != 3 { return Err(format!("proof file: proof kind {} is not Groth16 (3)", tag)) }
    let mut inputs = Vec::new();
    for _ in 0..5 { inputs.push(r.string()?); }
    let encoded = r.string()?;
    let raw = r.string()?;
    let vk_hash: [u8; 32] = r.take(32)?.try_into().unwrap();
    let public_values = r.bytes()?.to_vec();
    let sp1_version = r.string()?;
    let tee = r.take(1)?[0];
    if tee != 0 { return Err("proof file: carries a TEE proof (not a BECOME release proof)".into()) }
    if r.i != b.len() { return Err("proof file: trailing bytes after the proof".into()) }
    let mut onchain = vk_hash[..4].to_vec();
    onchain.extend(unhex(&encoded)?);
    let public_inputs: [String; 5] = inputs.try_into().unwrap();
    Ok(ProofBin { vkey_input: public_inputs[0].clone(), onchain_bytes: onchain, public_values, sp1_version, public_inputs, encoded, raw, vk_hash })
}

/// Decimal string (< 2^256) -> "0x" + 64 hex digits, to compare public input 0 with the pinned vkey.
pub fn dec_to_hex32(d: &str) -> Option<String> {
    if d.is_empty() || !d.bytes().all(|c| c.is_ascii_digit()) { return None }
    let mut n = [0u8; 32];
    for c in d.bytes() {
        let mut carry = (c - b'0') as u32;
        for x in n.iter_mut().rev() { let v = *x as u32 * 10 + carry; *x = v as u8; carry = v >> 8; }
        if carry != 0 { return None }
    }
    Some(format!("0x{}", n.iter().map(|x| format!("{:02x}", x)).collect::<String>()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn enc_str(v: &mut Vec<u8>, s: &str) { v.extend((s.len() as u64).to_le_bytes()); v.extend(s.as_bytes()); }
    fn sample(tag: u32, tee: u8, extra: bool) -> Vec<u8> {
        let mut v = tag.to_le_bytes().to_vec();
        for s in ["123", "1", "2", "3", "4"] { enc_str(&mut v, s); }
        enc_str(&mut v, "abcd"); enc_str(&mut v, "ef");
        v.extend([7u8; 32]);
        v.extend(200u64.to_le_bytes()); v.extend([0u8; 200]);
        enc_str(&mut v, "v6.1.0"); v.push(tee); if extra { v.push(0) } v
    }
    #[test] fn parses_groth16() {
        let p = parse(&sample(3, 0, false)).unwrap();
        assert_eq!(p.vkey_input, "123"); assert_eq!(p.onchain_bytes, vec![7, 7, 7, 7, 0xab, 0xcd]);
        assert_eq!(p.public_values.len(), 200); assert_eq!(p.sp1_version, "v6.1.0");
    }
    #[test] fn rejects_other_kind_tee_trailing_truncated() {
        assert!(parse(&sample(2, 0, false)).is_err());
        assert!(parse(&sample(3, 1, false)).is_err());
        assert!(parse(&sample(3, 0, true)).is_err());
        let s = sample(3, 0, false); assert!(parse(&s[..s.len() - 5]).is_err());
    }
    #[test] fn decimal_to_hex() {
        assert_eq!(dec_to_hex32("255").unwrap(), format!("0x{}ff", "0".repeat(62)));
        assert!(dec_to_hex32("1".repeat(80).as_str()).is_none());
    }
}
