package gateway

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type Counter struct {
	value uint64
}

func (c *Counter) Add(delta uint64) {
	atomic.AddUint64(&c.value, delta)
}

func (c *Counter) Value() uint64 {
	return atomic.LoadUint64(&c.value)
}

type Histogram struct {
	mu      sync.Mutex
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
}

func NewHistogram(buckets []float64) *Histogram {
	return &Histogram{
		buckets: buckets,
		counts:  make([]uint64, len(buckets)+1),
	}
}

func (h *Histogram) Observe(value float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.sum += value
	h.count++

	for i, bucket := range h.buckets {
		if value <= bucket {
			h.counts[i]++
			return
		}
	}
	h.counts[len(h.buckets)]++
}

type Metrics struct {
	ToolCalls       Counter
	ToolCallsByName map[string]uint64
	ToolDuration    *Histogram
	AuthSuccesses   Counter
	AuthFailures    Counter
	PolicyDenials   Counter
	RateLimited     Counter
	Errors          Counter

	mu sync.RWMutex
}

func NewMetrics() *Metrics {
	return &Metrics{
		ToolCallsByName: make(map[string]uint64),
		ToolDuration: NewHistogram([]float64{
			0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
		}),
	}
}

func (m *Metrics) WritePrometheus(w io.Writer) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fmt.Fprintf(w, "# HELP mcp_gateway_tool_calls_total Total number of tool calls\n")
	fmt.Fprintf(w, "# TYPE mcp_gateway_tool_calls_total counter\n")
	fmt.Fprintf(w, "mcp_gateway_tool_calls_total %d\n", m.ToolCalls.Value())

	fmt.Fprintf(w, "# HELP mcp_gateway_tool_calls_by_name Tool calls by tool name\n")
	fmt.Fprintf(w, "# TYPE mcp_gateway_tool_calls_by_name counter\n")
	for name, count := range m.ToolCallsByName {
		fmt.Fprintf(w, "mcp_gateway_tool_calls_by_name{tool=\"%s\"} %d\n", name, count)
	}

	fmt.Fprintf(w, "# HELP mcp_gateway_auth_successes_total Successful authentications\n")
	fmt.Fprintf(w, "# TYPE mcp_gateway_auth_successes_total counter\n")
	fmt.Fprintf(w, "mcp_gateway_auth_successes_total %d\n", m.AuthSuccesses.Value())

	fmt.Fprintf(w, "# HELP mcp_gateway_auth_failures_total Failed authentications\n")
	fmt.Fprintf(w, "# TYPE mcp_gateway_auth_failures_total counter\n")
	fmt.Fprintf(w, "mcp_gateway_auth_failures_total %d\n", m.AuthFailures.Value())

	fmt.Fprintf(w, "# HELP mcp_gateway_policy_denials_total Policy denials\n")
	fmt.Fprintf(w, "# TYPE mcp_gateway_policy_denials_total counter\n")
	fmt.Fprintf(w, "mcp_gateway_policy_denials_total %d\n", m.PolicyDenials.Value())

	fmt.Fprintf(w, "# HELP mcp_gateway_rate_limited_total Rate limited requests\n")
	fmt.Fprintf(w, "# TYPE mcp_gateway_rate_limited_total counter\n")
	fmt.Fprintf(w, "mcp_gateway_rate_limited_total %d\n", m.RateLimited.Value())

	fmt.Fprintf(w, "# HELP mcp_gateway_tool_duration_seconds Tool call duration\n")
	fmt.Fprintf(w, "# TYPE mcp_gateway_tool_duration_seconds histogram\n")
	m.ToolDuration.mu.Lock()
	cumulative := uint64(0)
	for i, bucket := range m.ToolDuration.buckets {
		cumulative += m.ToolDuration.counts[i]
		fmt.Fprintf(w, "mcp_gateway_tool_duration_seconds_bucket{le=\"%g\"} %d\n", bucket, cumulative)
	}
	cumulative += m.ToolDuration.counts[len(m.ToolDuration.buckets)]
	fmt.Fprintf(w, "mcp_gateway_tool_duration_seconds_bucket{le=\"+Inf\"} %d\n", cumulative)
	fmt.Fprintf(w, "mcp_gateway_tool_duration_seconds_sum %g\n", m.ToolDuration.sum)
	fmt.Fprintf(w, "mcp_gateway_tool_duration_seconds_count %d\n", m.ToolDuration.count)
	m.ToolDuration.mu.Unlock()

	fmt.Fprintf(w, "# HELP mcp_gateway_up Gateway is up\n")
	fmt.Fprintf(w, "# TYPE mcp_gateway_up gauge\n")
	fmt.Fprintf(w, "mcp_gateway_up 1\n")

	fmt.Fprintf(w, "# HELP mcp_gateway_info Gateway information\n")
	fmt.Fprintf(w, "# TYPE mcp_gateway_info gauge\n")
	fmt.Fprintf(w, "mcp_gateway_info{version=\"1.0.0\"} 1\n")

	fmt.Fprintf(w, "# HELP mcp_gateway_start_time_seconds Gateway start time\n")
	fmt.Fprintf(w, "# TYPE mcp_gateway_start_time_seconds gauge\n")
	fmt.Fprintf(w, "mcp_gateway_start_time_seconds %d\n", startTime.Unix())
}

var startTime = time.Now()
