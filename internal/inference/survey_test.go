package inference

import (
	"net/netip"
	"reflect"
	"testing"
)

func endpoint(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestObservationStoreInformationAndLifetime(t *testing.T) {
	var store Store
	first := Observation{endpoint("10.0.0.2:51000"), endpoint("192.0.2.10:40000"), endpoint("198.51.100.1:62000")}
	if !store.Add(first) || store.Add(first) || store.Add(Observation{}) {
		t.Fatal("incorrect novelty or validity")
	}
	second := first
	second.Remote = endpoint("192.0.2.11:40000")
	if !store.Add(second) {
		t.Fatal("same mapping at a new destination is new information")
	}
	snapshot := store.Snapshot()
	snapshot[0] = Observation{}
	if store.Snapshot()[0] != first {
		t.Fatal("snapshot aliases store")
	}
	store.ForgetLocal(first.Local)
	if len(store.Snapshot()) != 0 {
		t.Fatal("closed socket still has reusable evidence")
	}
}

func TestInferUsesAvailableEvidenceWithoutStage(t *testing.T) {
	input := SurveyInput{
		Local: endpoint("10.0.0.2:51000"), Target: endpoint("198.51.100.2:52000"),
		PublicIPs: []netip.Addr{netip.MustParseAddr("198.51.100.1")},
	}
	base := Infer(nil, input)
	if len(base.Candidates) != 1 || base.Candidates[0].Ranges[0].First != 51000 {
		t.Fatalf("baseline=%+v", base)
	}
	samples := []Observation{
		{input.Local, endpoint("192.0.2.10:40000"), endpoint("198.51.100.1:62731")},
		{input.Local, endpoint("192.0.2.11:40000"), endpoint("198.51.100.1:62731")},
	}
	prediction := Infer(samples, input)
	if len(prediction.Candidates) != 1 || prediction.Candidates[0].Basis != "shared-mapping-hypothesis" ||
		prediction.Candidates[0].Ranges[0].First != 62731 {
		t.Fatalf("rich evidence should directly yield the random but reusable port: %+v", prediction)
	}
	if !reflect.DeepEqual(prediction, Infer(samples, input)) {
		t.Fatal("Infer retained hidden stage")
	}
	input.BaseOnly = true
	input.Observers = []Observer{{Endpoints: []netip.AddrPort{endpoint("192.0.2.12:40000")}}}
	leaf := Infer(samples, input)
	if len(leaf.Plan) != 0 || leaf.Candidates[0].Ranges[0].First != 51000 {
		t.Fatalf("Observe leaf escaped baseline: %+v", leaf)
	}
}

func TestSurveyPlanOrdersResourcesAndObserverBranches(t *testing.T) {
	input := SurveyInput{
		Local: endpoint("10.0.0.2:51000"), Target: endpoint("198.51.100.2:52000"),
		Observers: []Observer{
			{Endpoints: []netip.AddrPort{endpoint("192.0.2.11:40000")}},
			{Bootstrap: true, Endpoints: []netip.AddrPort{endpoint("192.0.2.10:40000"), endpoint("192.0.2.10:40001")}},
		},
	}
	prediction := Infer(nil, input)
	if len(prediction.Plan) != 2 || !prediction.Plan[0].Bootstrap {
		t.Fatalf("plan=%+v", prediction.Plan)
	}
	steps := prediction.Plan[0].Steps
	if len(steps) != 6 || steps[0].Local != steps[1].Local || steps[2].Local.Port() != 51001 || steps[0].Remote == steps[1].Remote {
		t.Fatalf("plan does not preserve local-then-remote nesting: %+v", steps)
	}
	var observations []Observation
	for _, group := range prediction.Plan {
		for _, step := range group.Steps {
			observations = append(observations, Observation{step.Local, step.Remote, netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), step.Local.Port())})
		}
	}
	if next := Infer(observations, input); len(next.Plan) != 0 {
		t.Fatalf("re-requested already sampled tuples: %+v", next.Plan)
	}
}

func TestPredictionModelsAndUnconstrainedSpace(t *testing.T) {
	input := SurveyInput{Local: endpoint("10.0.0.2:51000"), Target: endpoint("198.51.100.2:52000")}
	for _, tc := range []struct {
		name  string
		ports []uint16
		want  string
	}{
		{"sequence", []uint16{42000, 42001, 42002}, "allocation-sequence-hypothesis"},
		{"unpredictable", []uint16{42000, 58001, 12002}, "unconstrained-port-space"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var observations []Observation
			for i, p := range tc.ports {
				observations = append(observations, Observation{input.Local,
					netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(40000+i)),
					netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), p)})
			}
			got := Infer(observations, input)
			if len(got.Candidates) != 1 || got.Candidates[0].Basis != tc.want {
				t.Fatalf("prediction=%+v", got)
			}
			if tc.name == "unpredictable" && got.Candidates[0].Ranges[0].Count() != 65535 {
				t.Fatal("broad candidate space silently truncated")
			}
		})
	}
}

func TestOffsetNeedsDistinctLocalSamplesAndEvidenceScope(t *testing.T) {
	input := SurveyInput{Local: endpoint("10.0.0.2:51003"), Target: endpoint("198.51.100.2:52000")}
	var observations []Observation
	for p := uint16(51000); p < 51003; p++ {
		observations = append(observations, Observation{
			netip.AddrPortFrom(input.Local.Addr(), p), endpoint("192.0.2.10:40000"),
			netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), p+7000)})
	}
	got := Infer(observations, input)
	found := false
	for _, batch := range got.Candidates {
		if batch.Basis == "local-port-offset-hypothesis" && batch.Ranges[0].First == 58003 {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing offset prediction: %+v", got)
	}
	input.Local = endpoint("10.1.0.2:51003")
	if got := Infer(observations, input); len(got.Candidates) != 0 {
		t.Fatalf("used another local address's samples: %+v", got)
	}
}
