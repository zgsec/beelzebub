package tracer

import (
	"encoding/json"
	"github.com/prometheus/client_golang/prometheus"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	mockStrategy := func(event Event) {}

	tracer := GetInstance(mockStrategy)

	assert.NotNil(t, tracer.strategy)
}

func TestTraceEvent(t *testing.T) {
	eventCalled := Event{}
	var wg sync.WaitGroup

	mockStrategy := func(event Event) {
		defer wg.Done()

		eventCalled = event
	}

	tracer := GetInstance(mockStrategy)

	// Use SetStrategy (mutex-guarded) rather than a raw field write — workers
	// read the strategy under the same lock, so a raw write here races them.
	tracer.SetStrategy(mockStrategy)

	wg.Add(1)
	tracer.TraceEvent(Event{
		ID:       "mockID",
		Protocol: HTTP.String(),
		Status:   Stateless.String(),
	})
	wg.Wait()

	assert.NotNil(t, eventCalled.ID)
	assert.Equal(t, "mockID", eventCalled.ID)
	assert.Equal(t, HTTP.String(), eventCalled.Protocol)
	assert.Equal(t, Stateless.String(), eventCalled.Status)
}

func TestSetStrategy(t *testing.T) {
	eventCalled := Event{}
	var wg sync.WaitGroup

	mockStrategy := func(event Event) {
		defer wg.Done()

		eventCalled = event
	}

	tracer := GetInstance(mockStrategy)

	tracer.SetStrategy(mockStrategy)

	wg.Add(1)
	tracer.TraceEvent(Event{
		ID:       "mockID",
		Protocol: HTTP.String(),
		Status:   Stateless.String(),
	})
	wg.Wait()

	assert.NotNil(t, eventCalled.ID)
	assert.Equal(t, "mockID", eventCalled.ID)
	assert.Equal(t, HTTP.String(), eventCalled.Protocol)
	assert.Equal(t, Stateless.String(), eventCalled.Status)
}

func TestStringStatus(t *testing.T) {
	assert.Equal(t, Start.String(), "Start")
	assert.Equal(t, End.String(), "End")
	assert.Equal(t, Stateless.String(), "Stateless")
	assert.Equal(t, Interaction.String(), "Interaction")
}

type mockCounter struct {
	prometheus.Metric
	prometheus.Collector
	inc func()
	add func(float64)
}

var counter = 0

func (m mockCounter) Inc() {
	counter += 1
}

func (m mockCounter) Add(f float64) {
	counter = int(f)
}

func TestUpdatePrometheusCounters(t *testing.T) {
	mockStrategy := func(event Event) {}

	tracer := &tracer{
		strategy:          mockStrategy,
		eventsChan:        make(chan Event, Workers),
		eventsTotal:       mockCounter{},
		eventsSSHTotal:    mockCounter{},
		eventsTCPTotal:    mockCounter{},
		eventsHTTPTotal:   mockCounter{},
		eventsMCPTotal:    mockCounter{},
		eventsTelnetTotal: mockCounter{},
	}

	tracer.updatePrometheusCounters(SSH.String())
	assert.Equal(t, 2, counter)

	tracer.updatePrometheusCounters(HTTP.String())
	assert.Equal(t, 4, counter)

	tracer.updatePrometheusCounters(TCP.String())
	assert.Equal(t, 6, counter)

	tracer.updatePrometheusCounters(MCP.String())
	assert.Equal(t, 8, counter)

	tracer.updatePrometheusCounters(TELNET.String())
	assert.Equal(t, 10, counter)
}

func TestGetStrategy(t *testing.T) {
	mockStrategy := func(event Event) {}

	tracer := GetInstance(mockStrategy)

	retrievedStrategy := tracer.GetStrategy()
	assert.NotNil(t, retrievedStrategy)
}

func TestSetGetStrategyConcurrency(t *testing.T) {
	tracer := GetInstance(func(event Event) {})

	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(2)

		go func(id int) {
			defer wg.Done()
			mockStrategy := func(event Event) {}
			tracer.SetStrategy(mockStrategy)
		}(i)

		go func(id int) {
			defer wg.Done()
			strategy := tracer.GetStrategy()
			assert.NotNil(t, strategy)
		}(i)
	}

	wg.Wait()
}

func TestEvent_CapturedFieldOmitsWhenNil(t *testing.T) {
	e := Event{Protocol: "HTTP"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"Captured"`) {
		t.Fatalf("nil Captured should be omitted: %s", b)
	}
}

func TestEvent_CapturedFieldSerializes(t *testing.T) {
	e := Event{
		Protocol: "HTTP",
		Captured: map[string]string{"screenconnect.operator_user": "pwn"},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"screenconnect.operator_user":"pwn"`) {
		t.Fatalf("Captured not serialized: %s", b)
	}
}

// TestEvent_RequestResponseBodyJSONContract locks in the cross-repo JSON tag
// contract for the WS-4 Slice B follow-on body-bytes fields. The
// honeypot.observer exporter's RawEvent struct (exporter/models/models.go,
// PR-2b 2026-05-25) parses these JSON keys verbatim:
//
//	RequestBody  string `json:"RequestBody,omitempty"`
//	ResponseBody string `json:"ResponseBody,omitempty"`
//
// If the JSON tag on the producer side drifts (Pascal → snake, or rename),
// the exporter silently drops the body bytes — exactly the failure mode that
// produced the dangling-resp_body_sha256 references PR-2b set out to fix.
// This test catches that drift at producer-side build time.
func TestEvent_RequestResponseBodyJSONContract(t *testing.T) {
	e := Event{
		Protocol:     "HTTP",
		RequestBody:  `{"model":"x","prompt":"y"}`,
		ResponseBody: `{"choices":[{"message":{"content":"z"}}]}`,
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if !strings.Contains(js, `"RequestBody":"{\"model\":\"x\",\"prompt\":\"y\"}"`) {
		t.Fatalf("RequestBody JSON tag drift — exporter PR-2b expects key 'RequestBody' verbatim. Got: %s", js)
	}
	if !strings.Contains(js, `"ResponseBody":"{\"choices\":[{\"message\":{\"content\":\"z\"}}]}"`) {
		t.Fatalf("ResponseBody JSON tag drift — exporter PR-2b expects key 'ResponseBody' verbatim. Got: %s", js)
	}
}

// TestEvent_RequestResponseBodyOmitWhenEmpty — the omitempty contract must
// hold so empty bodies don't bloat every event JSON line in the docker logs.
// A 200-byte event x 100k sessions/day = 20 MB/day of "" overhead at the
// sensor → exporter boundary.
func TestEvent_RequestResponseBodyOmitWhenEmpty(t *testing.T) {
	e := Event{Protocol: "HTTP"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if strings.Contains(js, `"RequestBody"`) {
		t.Fatalf("empty RequestBody must be omitted (omitempty): %s", js)
	}
	if strings.Contains(js, `"ResponseBody"`) {
		t.Fatalf("empty ResponseBody must be omitted (omitempty): %s", js)
	}
}
