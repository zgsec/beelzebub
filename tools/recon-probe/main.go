// Command recon-probe is a thin JSONL harness over the OLLAMA deterministic
// recon-responder, used by the cross-repo answer-gate
// (honeypot-research/tests/test_recon_answer_gate.py). It maps each probe to the
// EXACT production path — ExtractFeatures -> RespondFromFeatures — so the gate
// grades the real responder, not a copy.
//
// stdin:  one JSON object per line: {"probe": "...", "model": "..."}
// stdout: one JSON object per line: {"output": "...", "delivered": true|false}
package main

import (
	"bufio"
	"encoding/json"
	"os"

	ollama "github.com/mariocandela/beelzebub/v3/protocols/strategies/OLLAMA"
)

type in struct {
	Probe string `json:"probe"`
	Model string `json:"model"`
}

type out struct {
	Output    string `json:"output"`
	Delivered bool   `json:"delivered"`
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	enc := json.NewEncoder(os.Stdout)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var q in
		if err := json.Unmarshal(line, &q); err != nil {
			continue
		}
		model := q.Model
		if model == "" {
			model = "llama3.1:70b"
		}
		fv := ollama.ExtractFeatures(q.Probe)
		ans, ok := ollama.RespondFromFeatures(fv, model)
		_ = enc.Encode(out{Output: ans, Delivered: ok})
	}
}
