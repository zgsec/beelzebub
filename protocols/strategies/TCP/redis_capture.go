package TCP

import (
	"bytes"
	"strings"
)

// redisParseArgs parses a RESP2 multi-bulk array frame into its raw argument
// byte-slices. Returns nil on a non-array header or a malformed/truncated frame.
// It mirrors the bulk-walk in decodeProtocolCommand but preserves raw bytes
// (binary-safe) instead of joining to a string.
func redisParseArgs(b []byte) [][]byte {
	if len(b) == 0 || b[0] != '*' {
		return nil
	}
	hdrEnd := bytes.Index(b, []byte("\r\n"))
	if hdrEnd < 1 {
		return nil
	}
	count := 0
	for _, c := range b[1:hdrEnd] {
		if c < '0' || c > '9' {
			return nil
		}
		count = count*10 + int(c-'0')
	}
	if count <= 0 || count > 1024 {
		return nil
	}
	args := make([][]byte, 0, count)
	pos := hdrEnd + 2
	for i := 0; i < count; i++ {
		if pos >= len(b) || b[pos] != '$' {
			return nil
		}
		lenEnd := bytes.Index(b[pos:], []byte("\r\n"))
		if lenEnd < 0 {
			return nil
		}
		lenEnd += pos
		bulkLen := 0
		for _, c := range b[pos+1 : lenEnd] {
			if c < '0' || c > '9' {
				return nil
			}
			bulkLen = bulkLen*10 + int(c-'0')
		}
		valStart := lenEnd + 2
		valEnd := valStart + bulkLen
		if bulkLen < 0 || valEnd > len(b) {
			return nil // truncated/oversized -> not a complete frame
		}
		args = append(args, b[valStart:valEnd])
		pos = valEnd + 2
	}
	return args
}

var redisWriteVerbs = map[string]bool{
	"set": true, "setex": true, "psetex": true, "setnx": true,
	"append": true, "getset": true, "restore": true,
}

const redisCaptureMinBytes = 512

var redisStagingKeyHints = []string{"cron", "dbfilename", "module", ".so", "backup", "rdb"}

// shouldCaptureRedisValue returns true when a write command's value is
// payload-shaped: large (≥512 B), contains a binary/non-printable byte, or
// the key matches an RCE-staging hint substring (case-insensitive).
func shouldCaptureRedisValue(key string, value []byte) bool {
	if len(value) >= redisCaptureMinBytes {
		return true
	}
	for _, by := range value {
		if by < 0x09 || (by > 0x0d && by < 0x20) || by == 0x7f {
			return true // non-printable / binary
		}
	}
	lk := strings.ToLower(key)
	for _, h := range redisStagingKeyHints {
		if strings.Contains(lk, h) {
			return true
		}
	}
	return false
}

// redisWriteValue returns the key + raw value bytes of a payload-bearing write
// command, or ok=false. For SETEX/PSETEX/RESTORE the value is the LAST argument.
func redisWriteValue(b []byte) (key string, value []byte, ok bool) {
	args := redisParseArgs(b)
	if len(args) < 3 {
		return "", nil, false
	}
	verb := string(bytes.ToLower(args[0]))
	if !redisWriteVerbs[verb] {
		return "", nil, false
	}
	return string(args[1]), args[len(args)-1], true
}
