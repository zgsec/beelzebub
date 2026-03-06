package MCP

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// User represents a mutable user record in the world state.
type User struct {
	ID        string `yaml:"id" json:"id"`
	Email     string `yaml:"email" json:"email"`
	Role      string `yaml:"role" json:"role"`
	Active    bool   `json:"active"`
	LastLogin string `yaml:"lastLogin" json:"last_login"`
}

// LogEntry represents a queryable log entry.
type LogEntry struct {
	Timestamp string `yaml:"ts" json:"ts"`
	Level     string `yaml:"level" json:"level"`
	Message   string `yaml:"msg" json:"msg"`
}

// ActionRecord is an audit trail entry of tool actions performed.
type ActionRecord struct {
	Tool      string    `json:"tool"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
}

// WorldSeed is the YAML-parseable initial state for a world.
type WorldSeed struct {
	Users     []UserSeed        `yaml:"users"`
	Resources map[string]string `yaml:"resources"`
	Logs      []LogEntry        `yaml:"logs"`
}

// UserSeed is the YAML representation of a user for seeding.
type UserSeed struct {
	ID        string `yaml:"id"`
	Email     string `yaml:"email"`
	Role      string `yaml:"role"`
	LastLogin string `yaml:"lastLogin"`
}

// WorldState maintains mutable state for a single IP's MCP session.
type WorldState struct {
	mu        sync.RWMutex
	Users     map[string]*User
	Logs      []LogEntry
	Resources map[string]string
	Actions   []ActionRecord
}

// NewWorldState creates a fresh WorldState from seed data.
func NewWorldState(seed WorldSeed) *WorldState {
	ws := &WorldState{
		Users:     make(map[string]*User),
		Resources: make(map[string]string),
		Logs:      make([]LogEntry, len(seed.Logs)),
	}

	for _, u := range seed.Users {
		ws.Users[u.ID] = &User{
			ID:        u.ID,
			Email:     u.Email,
			Role:      u.Role,
			Active:    true,
			LastLogin: u.LastLogin,
		}
	}

	copy(ws.Logs, seed.Logs)

	for k, v := range seed.Resources {
		ws.Resources[k] = v
	}

	return ws
}

// HandleToolCall processes a tool call against the world state and returns a JSON response.
func (ws *WorldState) HandleToolCall(toolName string, args map[string]interface{}) string {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	switch toolName {
	case "tool:user-account-manager":
		return ws.handleUserManager(args)
	case "tool:system-log":
		return ws.handleSystemLog(args)
	case "tool:resource-store":
		return ws.handleResourceStore(args)
	default:
		return ws.handleGeneric(toolName, args)
	}
}

func (ws *WorldState) handleUserManager(args map[string]interface{}) string {
	action, _ := args["action"].(string)
	userID, _ := args["user_id"].(string)

	switch action {
	case "list_users":
		users := make([]map[string]interface{}, 0, len(ws.Users))
		for _, u := range ws.Users {
			users = append(users, map[string]interface{}{
				"id":     u.ID,
				"email":  u.Email,
				"role":   u.Role,
				"active": u.Active,
			})
		}
		data, _ := json.Marshal(map[string]interface{}{"status": "success", "users": users})
		return string(data)

	case "get_details":
		u, ok := ws.Users[userID]
		if !ok || !u.Active {
			return `{"status":"error","message":"user not found"}`
		}
		return fmt.Sprintf(`{"status":"success","user":{"id":"%s","email":"%s","role":"%s","active":true,"last_login":"%s"}}`,
			u.ID, u.Email, u.Role, u.LastLogin)

	case "deactivate_account":
		u, ok := ws.Users[userID]
		if !ok {
			return `{"status":"error","message":"user not found"}`
		}
		u.Active = false
		ws.Actions = append(ws.Actions, ActionRecord{
			Tool: "user-manager", Action: "deactivate", Target: userID,
			Timestamp: time.Now(), Success: true,
		})
		return `{"status":"success","message":"account deactivated"}`

	case "reset_password":
		u, ok := ws.Users[userID]
		if !ok || !u.Active {
			return `{"status":"error","message":"user not found or inactive"}`
		}
		ws.Actions = append(ws.Actions, ActionRecord{
			Tool: "user-manager", Action: "reset_password", Target: userID,
			Timestamp: time.Now(), Success: true,
		})
		prefix := userID
		if len(prefix) > 4 {
			prefix = prefix[:4]
		}
		return fmt.Sprintf(`{"status":"success","temporary_password":"Tmp-%s-2026!","expires_in":"24h"}`, prefix)

	case "change_role":
		u, ok := ws.Users[userID]
		if !ok || !u.Active {
			return `{"status":"error","message":"user not found or inactive"}`
		}
		newRole, _ := args["role"].(string)
		if newRole == "" {
			return `{"status":"error","message":"role required"}`
		}
		u.Role = newRole
		ws.Actions = append(ws.Actions, ActionRecord{
			Tool: "user-manager", Action: "change_role", Target: userID,
			Timestamp: time.Now(), Success: true,
		})
		return fmt.Sprintf(`{"status":"success","message":"role changed to %s"}`, newRole)
	}

	return `{"status":"error","message":"unknown action"}`
}

func (ws *WorldState) handleSystemLog(args map[string]interface{}) string {
	action, _ := args["action"].(string)

	switch action {
	case "query":
		level, _ := args["level"].(string)
		var filtered []LogEntry
		for _, l := range ws.Logs {
			if level == "" || l.Level == level {
				filtered = append(filtered, l)
			}
		}
		data, _ := json.Marshal(map[string]interface{}{"status": "success", "logs": filtered, "count": len(filtered)})
		return string(data)

	case "get_recent":
		n := 10
		if nf, ok := args["count"].(float64); ok {
			n = int(nf)
		}
		start := len(ws.Logs) - n
		if start < 0 {
			start = 0
		}
		data, _ := json.Marshal(map[string]interface{}{"status": "success", "logs": ws.Logs[start:]})
		return string(data)
	}

	return `{"status":"error","message":"unknown action"}`
}

func (ws *WorldState) handleResourceStore(args map[string]interface{}) string {
	action, _ := args["action"].(string)

	switch action {
	case "get":
		key, _ := args["key"].(string)
		if v, ok := ws.Resources[key]; ok {
			return fmt.Sprintf(`{"status":"success","key":"%s","value":"%s"}`, key, v)
		}
		return `{"status":"error","message":"key not found"}`

	case "list":
		keys := make([]string, 0, len(ws.Resources))
		for k := range ws.Resources {
			keys = append(keys, k)
		}
		data, _ := json.Marshal(map[string]interface{}{"status": "success", "keys": keys})
		return string(data)

	case "set":
		key, _ := args["key"].(string)
		value, _ := args["value"].(string)
		ws.Resources[key] = value
		ws.Actions = append(ws.Actions, ActionRecord{
			Tool: "resource-store", Action: "set", Target: key,
			Timestamp: time.Now(), Success: true,
		})
		return `{"status":"success","message":"resource updated"}`
	}

	return `{"status":"error","message":"unknown action"}`
}

func (ws *WorldState) handleGeneric(toolName string, args map[string]interface{}) string {
	ws.Actions = append(ws.Actions, ActionRecord{
		Tool: toolName, Action: "invoked", Target: fmt.Sprintf("%v", args),
		Timestamp: time.Now(), Success: true,
	})
	data, _ := json.Marshal(map[string]interface{}{
		"status":  "success",
		"tool":    toolName,
		"message": "operation completed",
	})
	return string(data)
}

// GetActions returns a copy of the action audit trail.
func (ws *WorldState) GetActions() []ActionRecord {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	result := make([]ActionRecord, len(ws.Actions))
	copy(result, ws.Actions)
	return result
}
