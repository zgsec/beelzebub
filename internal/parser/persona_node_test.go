package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNodeMinimal(t *testing.T) {
	dir := t.TempDir()
	nodeYAML := `schema_version: 1
node_id: test-01
role: test
persona_local:
  hostname: testhost
  fqdn: testhost.local
  os: ubuntu
  user: root
  internal_ip: 10.0.0.1
  uptime_days: 5
  process_seed: minimal
lures: []
`
	if err := os.WriteFile(filepath.Join(dir, "node.yaml"), []byte(nodeYAML), 0644); err != nil {
		t.Fatal(err)
	}
	n, err := LoadNode(dir)
	if err != nil {
		t.Fatalf("LoadNode: %v", err)
	}
	if n.NodeID != "test-01" {
		t.Errorf("NodeID = %q, want test-01", n.NodeID)
	}
	if n.PersonaLocal.Hostname != "testhost" {
		t.Errorf("Hostname = %q", n.PersonaLocal.Hostname)
	}
}

func TestLoadNodeWithProcesses(t *testing.T) {
	dir := t.TempDir()
	nodeYAML := `schema_version: 1
node_id: test
role: test
persona_local:
  hostname: h
  fqdn: h.local
  os: ubuntu
  user: root
  internal_ip: 10.0.0.1
  uptime_days: 1
  process_seed: x
  processes:
    - pid: 1
      user: root
      cpu: "0.0"
      mem: "0.1"
      vsz: "1000"
      rss: "100"
      cmd: /sbin/init
      stat: Ss
      time: "0:00"
lures: []
`
	if err := os.WriteFile(filepath.Join(dir, "node.yaml"), []byte(nodeYAML), 0644); err != nil {
		t.Fatal(err)
	}
	n, err := LoadNode(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.PersonaLocal.Processes) != 1 || n.PersonaLocal.Processes[0].Cmd != "/sbin/init" {
		t.Error("processes not parsed")
	}
}

func TestLoadNodeMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadNode(dir)
	if err == nil {
		t.Error("expected error for missing node.yaml")
	}
}
