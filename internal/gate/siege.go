package gate

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Choffolo/spikes402/internal/botid"
	"github.com/Choffolo/spikes402/internal/siegeart"
)

// The optional public siege view: a delayed, anonymised copy of the admin
// dashboard's siege monitor, for anyone visiting the site.
const (
	SiegePagePath = "/.spikes402/siege"
	SiegeJSONPath = "/.spikes402/siege.json"
)

const (
	// SiegeDelay is how far behind the public view runs. A second is only
	// published once it is this old, so nobody can watch their own
	// requests land in real time.
	SiegeDelay   = 8 * time.Second
	siegeShown   = 10 // seconds of events per snapshot
	siegeMinute  = 60 // seconds summed for the per-minute counters
	siegeSeconds = 80 // ring size: delay + minute, with room to spare
	siegeBots    = 6  // named bots kept per second; the rest count as unnamed
	siegeNameLen = 32
)

// Siege groups, the same four colours as the admin monitor.
const (
	siegePaid = iota
	siegePoW
	siegeHeld
	siegeRepelled
	siegeGroups
)

// PublicSiege aggregates gate events per second for the public siege view.
//
// It keeps no visitor data: no address, path, query, user agent or hash.
// Each second holds four counters and at most a few names of well-known
// crawlers (only those the bot list recognised). Memory is fixed.
//
// The JSON is rebuilt at most once per second into one shared snapshot;
// requests in the same second only copy those bytes.
type PublicSiege struct {
	now func() time.Time

	mu      sync.Mutex
	secs    [siegeSeconds]siegeSecond
	cache   []byte
	cacheAt int64 // unix second the cache was built for
	builds  int   // snapshots built, for tests
}

type siegeSecond struct {
	t     int64 // unix second, 0 means empty
	count [siegeGroups]uint32
	nbots int
	bots  [siegeBots]siegeBot
}

type siegeBot struct {
	name  string
	group int
	fake  bool
}

// NewPublicSiege returns an empty public siege view.
func NewPublicSiege() *PublicSiege { return &PublicSiege{now: time.Now} }

// SiegeSnapshot is the JSON body of GET /.spikes402/siege.json.
type SiegeSnapshot struct {
	DelaySeconds int           `json:"delay_seconds"`
	LastMinute   SiegeCounts   `json:"last_minute"`
	Seconds      []SiegeSecond `json:"seconds"`
}

// SiegeCounts are visits per colour.
type SiegeCounts struct {
	Paid     uint32 `json:"paid"`
	PoW      uint32 `json:"pow"`
	Held     uint32 `json:"held"`
	Repelled uint32 `json:"repelled"`
}

// SiegeSecond is one (delayed) second of visits.
type SiegeSecond struct {
	T int64 `json:"t"` // unix second
	SiegeCounts
	Bots []SiegeBot `json:"bots,omitempty"`
}

// SiegeBot is one visit by a crawler from the bot list. Fake means it
// claimed the name but its address did not check out.
type SiegeBot struct {
	Name  string `json:"name"`
	Group string `json:"group"`
	Fake  bool   `json:"fake,omitempty"`
}

var siegeGroupName = [siegeGroups]string{"paid", "pow", "held", "repelled"}

func siegeGroup(o Outcome) int {
	switch o {
	case OutcomePaid:
		return siegePaid
	case OutcomePoW, OutcomeFree:
		return siegePoW
	case OutcomeChallenged:
		return siegeHeld
	default:
		return siegeRepelled
	}
}

// siegeName is the bot's name if it is safe to show: a crawler from the
// configured bot list, verified or caught faking it. Signed agents (a
// URL) and unknown visitors get no name.
func siegeName(c botid.Class) (name string, fake bool) {
	if c.Kind != botid.Verified && c.Kind != botid.Impostor {
		return "", false
	}
	if c.Name == "" || len(c.Name) > siegeNameLen {
		return "", false
	}
	for _, r := range c.Name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ' ') {
			return "", false
		}
	}
	return c.Name, c.Kind == botid.Impostor
}

// Observe records one gate event: only its second, colour and, for a
// listed crawler, its name.
func (s *PublicSiege) Observe(e Event) {
	if s == nil {
		return
	}
	t := e.Time
	if t.IsZero() {
		t = s.now()
	}
	sec := t.Unix()
	grp := siegeGroup(e.Outcome)
	name, fake := siegeName(e.Class)
	s.mu.Lock()
	defer s.mu.Unlock()
	b := &s.secs[uint64(sec)%siegeSeconds]
	if b.t != sec {
		*b = siegeSecond{t: sec}
	}
	b.count[grp]++
	if name != "" && b.nbots < siegeBots {
		b.bots[b.nbots] = siegeBot{name: name, group: grp, fake: fake}
		b.nbots++
	}
}

// snapshotLocked builds the view for now: seconds older than SiegeDelay.
func (s *PublicSiege) snapshotLocked(now int64) SiegeSnapshot {
	last := now - int64(SiegeDelay/time.Second) // newest second shown
	snap := SiegeSnapshot{DelaySeconds: int(SiegeDelay / time.Second), Seconds: []SiegeSecond{}}
	for t := last - siegeMinute + 1; t <= last; t++ {
		b := &s.secs[uint64(t)%siegeSeconds]
		if b.t != t {
			continue
		}
		c := SiegeCounts{Paid: b.count[siegePaid], PoW: b.count[siegePoW], Held: b.count[siegeHeld], Repelled: b.count[siegeRepelled]}
		snap.LastMinute.Paid += c.Paid
		snap.LastMinute.PoW += c.PoW
		snap.LastMinute.Held += c.Held
		snap.LastMinute.Repelled += c.Repelled
		if t <= last-siegeShown {
			continue
		}
		out := SiegeSecond{T: t, SiegeCounts: c}
		for _, bot := range b.bots[:b.nbots] {
			out.Bots = append(out.Bots, SiegeBot{Name: bot.name, Group: siegeGroupName[bot.group], Fake: bot.fake})
		}
		snap.Seconds = append(snap.Seconds, out)
	}
	return snap
}

func (s *PublicSiege) cachedJSON() ([]byte, error) {
	now := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache != nil && s.cacheAt == now {
		return s.cache, nil
	}
	body, err := json.Marshal(s.snapshotLocked(now))
	if err != nil {
		return nil, err
	}
	s.cache = append(body, '\n')
	s.cacheAt = now
	s.builds++
	return s.cache, nil
}

// serveJSON answers GET/HEAD /.spikes402/siege.json from the shared snapshot.
func (s *PublicSiege) serveJSON(w http.ResponseWriter, r *http.Request) {
	if !getOrHead(w, r) {
		return
	}
	body, err := s.cachedJSON()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "public, max-age=1")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

// servePage answers GET/HEAD /.spikes402/siege with the static page.
func (s *PublicSiege) servePage(w http.ResponseWriter, r *http.Request) {
	if !getOrHead(w, r) {
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", siegeCSP)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		io.WriteString(w, siegePage)
	}
}

func getOrHead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

// siegeViewJS polls the snapshot (at most once a second, only while the
// tab is visible) and draws new seconds with the shared siege art.
const siegeViewJS = `(function(){
"use strict";
var art=SiegeArt.create(document.getElementById("sprites")),G=["paid","pow","held","repelled"];
var still=matchMedia("(prefers-reduced-motion: reduce)"),last=0,timer=0,busy=false;
var TIP={paid:"paid \u26a1",pow:"did the work",held:"stopped (402)",repelled:"repelled"};
function n(x){return Number(x||0).toLocaleString("en")}
function show(s){
  var m=s.last_minute||{};
  G.forEach(function(g){document.getElementById("s-"+g).textContent=n(m[g])});
  var fresh=(s.seconds||[]).filter(function(x){return x.t>last});
  if(fresh.length&&last&&!still.matches){
    fresh.forEach(function(x,i){
      var dots=[];
      (x.bots||[]).forEach(function(b){var nm=b.name+(b.fake?" (fake)":"");dots.push([b.group,nm,nm+" \u00b7 "+(TIP[b.group]||"")])});
      var named={};(x.bots||[]).forEach(function(b){named[b.group]=(named[b.group]||0)+1});
      G.forEach(function(g){for(var k=Math.min(12,(x[g]||0)-(named[g]||0));k>0;k--)dots.push([g,"",TIP[g]])});
      dots=dots.slice(0,12);
      dots.forEach(function(d,j){setTimeout(function(){art.spawn(d[0],d[1],d[2])},(i*1000+j*1000/dots.length)/fresh.length)});
    });
  }
  (s.seconds||[]).forEach(function(x){if(x.t>last)last=x.t});
}
function poll(){
  if(busy||document.hidden)return;
  busy=true;
  fetch("` + SiegeJSONPath + `",{cache:"no-store"}).then(function(r){if(!r.ok)throw 0;return r.json()}).then(show).catch(function(){}).then(function(){busy=false});
}
function start(){if(!timer&&!document.hidden){poll();timer=setInterval(poll,1000)}}
function stop(){clearInterval(timer);timer=0}
document.addEventListener("visibilitychange",function(){document.hidden?stop():start()});
function frame(t){art.frame(t);requestAnimationFrame(frame)}
requestAnimationFrame(frame);
start();
})();`

const siegeCSS = `:root{--bg:#0b1020;--card:#141b33;--fg:#e6ebff;--dim:#8a93b8;--line:#222b4d;--paid:#ffc83d;--pow:#00e5ff;--held:#9aa3c7;--repelled:#ff4d6d}
body{margin:0 auto;max-width:960px;padding:1rem;font:15px/1.45 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
a{color:var(--pow)}h1{font-size:1.4rem;margin:.2rem 0 .8rem;display:flex;align-items:center;gap:.5rem}
h1 .logo{width:1.6em;height:1.6em;flex:none;background:var(--fg);border-radius:50%;padding:2px}h1 a.logo-link{color:inherit;text-decoration:none;display:flex;flex:none}.note{color:var(--dim);font-size:13px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:.8rem;margin-bottom:.8rem}
.stats div{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:.5rem .9rem;color:var(--dim);font-size:13px}
.stats b{display:block;font-size:1.8rem;color:var(--fg);font-variant-numeric:tabular-nums}
.stats .paid b{color:var(--paid)}.stats .pow b{color:var(--pow)}.stats .held b{color:var(--held)}.stats .repelled b{color:var(--repelled)}
#field{width:100%;height:auto;background:radial-gradient(ellipse at 20% 50%,#161338 0%,var(--bg) 70%);border:1px solid var(--line);border-radius:10px;display:block}
.wall{fill:var(--pow);fill-opacity:.35;stroke:var(--pow);animation:glow 5s ease-in-out infinite}
.citadel rect{fill:#1a2347;stroke:#3a4a8a}@keyframes glow{50%{fill-opacity:.6}}
.sprite text{font-size:11px;fill:var(--dim)}
.legend{display:flex;gap:1.2rem;flex-wrap:wrap;color:var(--dim);font-size:13px}
.legend i{display:inline-block;width:.7rem;height:.7rem;border-radius:50%;margin-right:.35rem;vertical-align:-1px}
.legend .paid{background:var(--paid)}.legend .pow{background:var(--pow)}.legend .held{background:var(--held)}.legend .repelled{background:var(--repelled)}
@media (max-width:640px){.stats{grid-template-columns:repeat(2,1fr)}}
@media (prefers-reduced-motion:reduce){.wall{animation:none}}`

var (
	siegePage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>The siege · Spikes402</title>
<link rel="icon" href="` + string(logoFavicon) + `" type="image/svg+xml">
<style>` + siegeCSS + `</style>
</head>
<body>
<h1>` + string(logoHome) + ` The siege</h1>
<p class="note">Every dot is a visit to a protected page. Delayed a few seconds (about ` + itoaWait(SiegeDelay) + ` s) and anonymised: no addresses, pages or user agents, only the names of well-known crawlers.</p>
<div class="stats" aria-live="off">
<div class="paid"><b id="s-paid">0</b>paid / min</div>
<div class="pow"><b id="s-pow">0</b>proof-of-work / min</div>
<div class="held"><b id="s-held">0</b>stopped / min</div>
<div class="repelled"><b id="s-repelled">0</b>repelled / min</div>
</div>
<svg id="field" viewBox="0 0 1000 400" role="img" aria-label="Visitors approaching the protected walls">
<rect x="628" y="30" width="24" height="150" class="wall"/>
<rect x="628" y="230" width="24" height="150" class="wall"/>
<g class="citadel"><rect x="790" y="150" width="150" height="180"/><rect x="770" y="110" width="40" height="220"/><rect x="920" y="110" width="40" height="220"/></g>
<g id="sprites"></g>
</svg>
<p class="legend"><span><i class="paid"></i>paid ⚡</span><span><i class="pow"></i>did the work</span><span><i class="held"></i>stopped at the wall</span><span><i class="repelled"></i>repelled</span></p>
<p class="note"><a href="/">Back to the site</a> · Protected by <a href="https://github.com/Choffolo/spikes402">Spikes402</a>.</p>
<script>` + siegeart.JS + `</script>
<script>` + siegeViewJS + `</script>
</body>
</html>
`
	siegeCSP = "default-src 'none'; img-src data:; style-src 'sha256-" + b64sha(siegeCSS) + "'; script-src 'sha256-" + b64sha(siegeart.JS) + "' 'sha256-" + b64sha(siegeViewJS) +
		"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

func b64sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.StdEncoding.EncodeToString(h[:])
}
