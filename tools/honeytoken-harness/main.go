// honeytoken-harness exposes the REAL honeytoken-wired MCP WorldState over a tiny
// HTTP API so a selectivity study can drive agents/scripts/crawlers at it and read
// the fires. Local-only; research instrument, not a deployable lure.
//
//	POST /call   {"session":"id","tool":"read_file","args":{"path":"/app/.env"}}
//	GET  /fires?session=id
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	mcp "github.com/mariocandela/beelzebub/v3/protocols/strategies/MCP"
)

var (
	mu     sync.Mutex
	worlds = map[string]*mcp.WorldState{}
)

func getWorld(session string) *mcp.WorldState {
	mu.Lock()
	defer mu.Unlock()
	if w, ok := worlds[session]; ok {
		return w
	}
	w := mcp.NewWorldState(mcp.WorldSeed{}, nil)
	w.Honeytoken = mcp.MintHoneytokens(session, "")
	worlds[session] = w
	return w
}

func main() {
	http.HandleFunc("/call", func(wr http.ResponseWriter, r *http.Request) {
		var req struct {
			Session string                 `json:"session"`
			Tool    string                 `json:"tool"`
			Args    map[string]interface{} `json:"args"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(wr, err.Error(), 400)
			return
		}
		if req.Session == "" {
			req.Session = "default"
		}
		wr.Header().Set("Content-Type", "application/json")
		wr.Write([]byte(getWorld(req.Session).HandleToolCall(req.Tool, req.Args)))
	})

	http.HandleFunc("/fires", func(wr http.ResponseWriter, r *http.Request) {
		session := r.URL.Query().Get("session")
		mu.Lock()
		w := worlds[session]
		mu.Unlock()
		out := map[string]interface{}{"session": session, "confirmed_agent": false, "fired": []mcp.HoneytokenFire{}}
		if w != nil && w.Honeytoken != nil {
			out["fired"] = w.Honeytoken.Fired
			out["confirmed_agent"] = w.Honeytoken.HasDeductiveAgent()
		}
		wr.Header().Set("Content-Type", "application/json")
		json.NewEncoder(wr).Encode(out)
	})

	fmt.Println("honeytoken harness on 127.0.0.1:8799")
	http.ListenAndServe("127.0.0.1:8799", nil)
}
