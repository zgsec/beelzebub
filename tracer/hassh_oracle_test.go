package tracer

import "testing"

// Oracle vector from the canonical Salesforce hassh reference README
// (github.com/salesforce/hassh) — the documented Cyberduck client example.
// Reproducing the documented MD5 from the exact client algorithm lists proves
// our KEXINIT parse + HASSH hashing match the reference (cross-corpus with the
// hassh corpus), not merely that we emit a 32-char hex string.
//
// HASSH = md5(kex ; enc_c2s ; mac_c2s ; comp_c2s).
func TestComputeHASSH_SalesforceCyberduckOracle(t *testing.T) {
	kex := "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group15-sha512,diffie-hellman-group16-sha512,diffie-hellman-group17-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256@ssh.com,diffie-hellman-group15-sha256,diffie-hellman-group15-sha256@ssh.com,diffie-hellman-group15-sha384@ssh.com,diffie-hellman-group16-sha256,diffie-hellman-group16-sha384@ssh.com,diffie-hellman-group16-sha512@ssh.com,diffie-hellman-group18-sha512@ssh.com"
	enc := "aes128-cbc,aes128-ctr,aes192-cbc,aes192-ctr,aes256-cbc,aes256-ctr,blowfish-cbc,blowfish-ctr,cast128-cbc,cast128-ctr,idea-cbc,idea-ctr,serpent128-cbc,serpent128-ctr,serpent192-cbc,serpent192-ctr,serpent256-cbc,serpent256-ctr,3des-cbc,3des-ctr,twofish128-cbc,twofish128-ctr,twofish192-cbc,twofish192-ctr,twofish256-cbc,twofish256-ctr,twofish-cbc,arcfour,arcfour128,arcfour256"
	mac := "hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-sha2-256,hmac-sha2-512"
	comp := "zlib@openssh.com,zlib,none"
	const want = "8a8ae540028bf433cd68356c1b9e8d5b"

	raw := buildKEXINIT(kex, enc, mac, comp)
	if got := ComputeHASSH(raw); got != want {
		t.Errorf("HASSH mismatch vs Salesforce oracle:\n  want %q\n  got  %q", want, got)
	}
	// ComputeHASSHFull must agree and expose the exact reference input string.
	full := ComputeHASSHFull(raw)
	if full == nil || full.Hash != want {
		t.Fatalf("ComputeHASSHFull mismatch: %+v", full)
	}
	if wantInput := kex + ";" + enc + ";" + mac + ";" + comp; full.RawInput != wantInput {
		t.Errorf("HASSH raw input string mismatch:\n  want %q\n  got  %q", wantInput, full.RawInput)
	}
}
