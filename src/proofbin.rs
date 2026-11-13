// SDK-free reader for SP1 6.8.1 `SP1ProofWithPublicValues` files as `.save()` writes them (bincode, little-endian,
// u64 length prefixes). Accepts exactly a Groth16 proof with no TEE proof and no trailing bytes.
pub struct ProofBin {
    pub vkey_input: String,      // public_inputs[0]: the program vkey as a decimal string
    pub onchain_bytes: Vec<u8>,  // groth16_vkey_hash[..4] ++ hex-decoded encoded_proof (= SP1ProofWithPublicValues::bytes())
    pub public_values: Vec<u8>,
    pub sp1_version: String,
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
    let _raw = r.string()?;
    let vk_hash = r.take(32)?.to_vec();
    let public_values = r.bytes()?.to_vec();
    let sp1_version = r.string()?;
    let tee = r.take(1)?[0];
    if tee != 0 { return Err("proof file: carries a TEE proof (not a BECOME release proof)".into()) }
    if r.i != b.len() { return Err("proof file: trailing bytes after the proof".into()) }
    let mut onchain = vk_hash[..4].to_vec();
    onchain.extend(unhex(&encoded)?);
    Ok(ProofBin { vkey_input: inputs[0].clone(), onchain_bytes: onchain, public_values, sp1_version })
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
