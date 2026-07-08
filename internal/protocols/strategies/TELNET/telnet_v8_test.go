package TELNET

import (
	"testing"
)

// TestParseIACSubneg_NAWS verifies NAWS (Window Size) extraction.
// Real terminals send: IAC SB NAWS <width-hi> <width-lo> <height-hi> <height-lo> IAC SE
func TestParseIACSubneg_NAWS(t *testing.T) {
	// 80x24 terminal (standard)
	data := []byte{
		IAC, SB, 31, // NAWS option
		0, 80, // width = 80
		0, 24, // height = 24
		IAC, SE,
	}
	result := parseIACSubnegotiations(data)
	if result.WindowWidth != 80 || result.WindowHeight != 24 {
		t.Errorf("expected 80x24, got %dx%d", result.WindowWidth, result.WindowHeight)
	}
}

func TestParseIACSubneg_NAWS_Large(t *testing.T) {
	// 120x40 (larger terminal — human signal)
	data := []byte{
		IAC, SB, 31,
		0, 120,
		0, 40,
		IAC, SE,
	}
	result := parseIACSubnegotiations(data)
	if result.WindowWidth != 120 || result.WindowHeight != 40 {
		t.Errorf("expected 120x40, got %dx%d", result.WindowWidth, result.WindowHeight)
	}
}

func TestParseIACSubneg_NAWS_Zero(t *testing.T) {
	// 0x0 — bot that doesn't implement NAWS properly
	data := []byte{
		IAC, SB, 31,
		0, 0, 0, 0,
		IAC, SE,
	}
	result := parseIACSubnegotiations(data)
	if result.WindowWidth != 0 || result.WindowHeight != 0 {
		t.Errorf("expected 0x0, got %dx%d", result.WindowWidth, result.WindowHeight)
	}
}

func TestParseIACSubneg_TTYPE(t *testing.T) {
	// Terminal type: xterm-256color
	ttype := "xterm-256color"
	data := []byte{IAC, SB, 24, 0x00} // TTYPE, IS
	data = append(data, []byte(ttype)...)
	data = append(data, IAC, SE)

	result := parseIACSubnegotiations(data)
	if result.TermType != ttype {
		t.Errorf("expected %q, got %q", ttype, result.TermType)
	}
}

func TestParseIACSubneg_TTYPE_VT100(t *testing.T) {
	ttype := "VT100"
	data := []byte{IAC, SB, 24, 0x00}
	data = append(data, []byte(ttype)...)
	data = append(data, IAC, SE)

	result := parseIACSubnegotiations(data)
	if result.TermType != ttype {
		t.Errorf("expected %q, got %q", ttype, result.TermType)
	}
}

func TestParseIACSubneg_TSPEED(t *testing.T) {
	speed := "38400,38400"
	data := []byte{IAC, SB, 32, 0x00} // TSPEED, IS
	data = append(data, []byte(speed)...)
	data = append(data, IAC, SE)

	result := parseIACSubnegotiations(data)
	if result.TermSpeed != speed {
		t.Errorf("expected %q, got %q", speed, result.TermSpeed)
	}
}

func TestParseIACSubneg_Combined(t *testing.T) {
	// Real client sends NAWS + TTYPE + TSPEED together
	var data []byte
	// NAWS
	data = append(data, IAC, SB, 31, 0, 132, 0, 43, IAC, SE)
	// TTYPE
	data = append(data, IAC, SB, 24, 0x00)
	data = append(data, []byte("PuTTY")...)
	data = append(data, IAC, SE)
	// TSPEED
	data = append(data, IAC, SB, 32, 0x00)
	data = append(data, []byte("9600,9600")...)
	data = append(data, IAC, SE)

	result := parseIACSubnegotiations(data)
	if result.WindowWidth != 132 || result.WindowHeight != 43 {
		t.Errorf("NAWS: expected 132x43, got %dx%d", result.WindowWidth, result.WindowHeight)
	}
	if result.TermType != "PuTTY" {
		t.Errorf("TTYPE: expected PuTTY, got %q", result.TermType)
	}
	if result.TermSpeed != "9600,9600" {
		t.Errorf("TSPEED: expected 9600,9600, got %q", result.TermSpeed)
	}
}

// --- Crash resistance tests ---
// These simulate MALFORMED input that an attacker could send to crash the sensor.

func TestParseIACSubneg_Empty(t *testing.T) {
	result := parseIACSubnegotiations([]byte{})
	if result.TermType != "" || result.WindowWidth != 0 {
		t.Error("non-zero result from empty input")
	}
}

func TestParseIACSubneg_TruncatedNAWS(t *testing.T) {
	// NAWS with only 2 bytes instead of 4
	data := []byte{IAC, SB, 31, 0, 80, IAC, SE}
	// Should not panic — just produce partial or zero values
	result := parseIACSubnegotiations(data)
	_ = result // no crash = pass
}

func TestParseIACSubneg_NoSE(t *testing.T) {
	// SB without matching SE — parser must not loop forever
	data := []byte{IAC, SB, 31, 0, 80, 0, 24}
	result := parseIACSubnegotiations(data)
	_ = result // no hang, no crash = pass
}

func TestParseIACSubneg_GarbageBytes(t *testing.T) {
	// Random bytes that aren't valid IAC sequences
	data := []byte{0x41, 0x42, 0x43, 0xFF, 0x01, 0x02, 0x00, 0xFF, 0xFB, 0x01}
	result := parseIACSubnegotiations(data)
	_ = result // no crash = pass
}

func TestParseIACSubneg_IACSEWithoutSB(t *testing.T) {
	// IAC SE without preceding SB
	data := []byte{IAC, SE, IAC, SE, IAC, SE}
	result := parseIACSubnegotiations(data)
	_ = result // no crash = pass
}

func TestParseIACSubneg_NestedIAC(t *testing.T) {
	// IAC IAC (escaped 0xFF byte) inside subnegotiation
	data := []byte{IAC, SB, 24, 0x00, IAC, IAC, IAC, SE}
	result := parseIACSubnegotiations(data)
	// The escaped IAC should appear as a single 0xFF in the data
	// Our simple parser doesn't handle IAC escaping — it will
	// see IAC IAC as end-of-subneg (wrong but safe).
	_ = result // no crash = pass
}

func TestParseIACSubneg_MaxLengthData(t *testing.T) {
	// Very long TTYPE string (attacker sending 10KB terminal type)
	data := []byte{IAC, SB, 24, 0x00}
	for i := 0; i < 10000; i++ {
		data = append(data, 'A')
	}
	data = append(data, IAC, SE)
	result := parseIACSubnegotiations(data)
	if len(result.TermType) != 10000 {
		t.Errorf("expected 10000 char term type, got %d", len(result.TermType))
	}
}

// --- Existing parseIACOptions tests (verify we didn't break the original parser) ---

func TestParseIACOptions_BasicNegotiation(t *testing.T) {
	data := []byte{
		IAC, WILL, ECHO,
		IAC, DO, SUPPRESS_GO_AHEAD,
		IAC, WILL, 31, // NAWS
	}
	summary := parseIACOptions(data)
	if summary != "WILL:ECHO,DO:SGA,WILL:NAWS" {
		t.Errorf("unexpected summary: %s", summary)
	}
}

func TestParseIACOptions_Empty(t *testing.T) {
	if parseIACOptions([]byte{}) != "" {
		t.Error("non-empty for empty input")
	}
}

func TestParseIACOptions_NoIAC(t *testing.T) {
	if parseIACOptions([]byte{0x41, 0x42, 0x43}) != "" {
		t.Error("non-empty for non-IAC input")
	}
}
