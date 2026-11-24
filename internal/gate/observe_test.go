package gate

import (
	"net/http"
	"testing"
)

func TestObserveOnlyMode(t *testing.T) {
	f := newFixture(t)
	var events []Event
	f.gate.opt.Observer = func(e Event) { events = append(events, e) }
	s := f.gate.Settings()
	s.ObserveOnly = true
	s.Prices = []PriceRule{{Pattern: "/premium/vip/**", PriceSats: 42}}
	if err := f.gate.UpdateSettings(s); err != nil {
		t.Fatal(err)
	}

	// Protected path is served free (200), creates no invoice, records OutcomeObserved with price.
	rec := f.get("/premium/vip/post", "", "text/html")
	if rec.Code != http.StatusOK {
		t.Fatalf("observe_only status = %d, want 200", rec.Code)
	}
	if got := f.gate.Status().Node.InvoicesCreated; got != 0 {
		t.Fatalf("observe_only created %d invoices, want 0", got)
	}
	if len(events) != 1 || events[0].Outcome != OutcomeObserved || events[0].Price != 42 {
		t.Fatalf("events = %+v, want 1 OutcomeObserved with Price=42", events)
	}
}
