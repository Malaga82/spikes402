package gate

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"net/http"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/Choffolo/spikes402/pow"
)

// The page shown to people who open a protected link in a browser.
// No external resources, no external scripts. Two small inline scripts:
// one talks to a WebLN wallet if the browser has one (for example Alby),
// the other runs the proof-of-work puzzle in Web Workers. Without
// JavaScript the page is still the invoice, the QR code and the text.
var page = template.Must(template.New("402").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{with .Preview}}{{with .Title}}{{.}} · {{end}}{{end}}402 Payment Required · Spikes402</title>
<link rel="icon" href="{{.Favicon}}" type="image/svg+xml">
{{with .Preview}}{{with .Description}}<meta name="description" content="{{.}}">
{{end}}{{end}}{{.LD}}
<style>
 body{font-family:system-ui,sans-serif;max-width:36rem;margin:1.5rem auto;padding:0 1rem;color:#222;line-height:1.35}
 h1{display:flex;align-items:center;gap:.45rem;font-size:1.9rem;margin:.2rem 0 .6rem}
 h1 .logo{width:1.5em;height:1.5em;flex:none}
 h1 a.logo-link{color:inherit;text-decoration:none;display:flex;flex:none}
 h2{font-size:1.05rem;margin:.15rem 0 .3rem}
 p{margin:.3rem 0}
 code{word-break:break-all;background:#f3f3f3;padding:.15rem .3rem;border-radius:4px;font-size:.8rem}
 img{display:block;margin:.4rem 0;image-rendering:pixelated}
 small{color:#666}
 article{border-left:4px solid #f7931a;padding:.05rem .8rem;margin:.5rem 0;background:#fafafa;font-size:.95rem}
 article h2{margin:.35rem 0 .15rem;font-size:1.05rem}
 article p{margin:.2rem 0}
 .paywall{margin-top:.6rem}
 #wallet-box,#pay-wait{margin:.4rem 0 0}
 #wallet-box button,#pow-go,a.btn{font:inherit;padding:.35rem .7rem}
 #pw-start{margin:.8rem 0}
 .pw-grid{display:grid;grid-template-columns:repeat(8,1.1rem);gap:.25rem;margin:.8rem 0 .6rem}
 .pw-grid i{display:block;height:1.1rem;border-radius:3px;background:#e8e8e8}
 .pw-grid i.on{background:#f7931a}
 #pw-status{font-weight:600;margin:.4rem 0}
 .pw-stats{color:#666;font-size:.85rem;font-variant-numeric:tabular-nums}
 .pw-note{color:#555;font-size:.85rem}
 .pw-hash{font:.75rem ui-monospace,monospace;color:#999;word-break:break-all;min-height:1em}
 #pw-zeros{color:#f7931a;font-weight:700}
 details{margin:.8rem 0} summary{cursor:pointer;font-size:1.05rem}
 a.btn{display:inline-block;border:1px solid #888;border-radius:4px;background:#f6f6f6;color:inherit;text-decoration:none}
 a.btn:hover{background:#eee}
 .err{color:#a00}
</style>
</head>
<body>
<h1>{{.Logo}}<span id="pw-title">{{if .Auto}}One moment{{else if .Solve}}Pay or PoW{{else}}Payment required{{end}}</span></h1>
<p id="pw-intro"{{if not .Auto}} hidden{{end}}>This page is protected against mass crawlers. Your browser does a short proof-of-work, then the page opens by itself.</p>
{{with .Preview}}<article>
{{with .Title}}<h2>{{.}}</h2>
{{end}}{{with .Description}}<p>{{.}}</p>
{{end}}{{with .Excerpt}}<p>{{.}}</p>
{{end}}<p><small>A taste of what is behind the wall.</small></p>
</article>
{{end}}<div class="paywall">
{{if .Solve}}<div id="pow-box" data-mode="{{.Mode}}" data-challenge="{{.PoW.Challenge}}" data-difficulty="{{.PoW.Difficulty}}" data-worker="{{.WorkerSrc}}"{{with .Lottery}} data-lottery="{{.Challenge}}" data-header="{{.Header}}"{{end}}>
<div id="pw-run" hidden>
<div class="pw-grid" aria-hidden="true">{{.Tiles}}</div>
<p id="pw-status" role="status">Starting…</p>
<p class="pw-stats"><span id="pw-what"></span> · <span id="pw-rate">–</span> · <span id="pw-tries">0</span> hashes</p>
<p class="pw-hash" title="Best hash so far"><span id="pw-zeros"></span><span id="pw-rest"></span></p>
<p class="pw-note" id="pw-note-lottery" hidden>Your browser computes double SHA-256 hashes, like Bitcoin, on a <strong>real Bitcoin block header</strong> from this site&rsquo;s solo pool: every hash is also a lottery ticket for a whole block. The odds are tiny, the work is not wasted. Nothing is installed, and it stops as soon as the page opens.</p>
<p class="pw-note" id="pw-note-sha" hidden>Your browser computes double SHA-256 hashes, like Bitcoin. The work only shows you are not a mass crawler, then it is thrown away.</p>
</div>
</div>
{{end}}<details id="pay"{{if not .Auto}} open{{end}}><summary{{if not .Auto}} hidden{{end}}>Pay {{.PriceSats}} {{.SatUnit}} with Lightning instead</summary>
<p>This page costs <strong>{{.PriceSats}} {{.SatUnit}}</strong>.</p>
{{with .L402}}
<p>Pay this Lightning invoice with any wallet, or in one click with the <a href="https://github.com/Choffolo/spikes402#browser-wallet-extension-prototype">Spikes402 extension</a>:</p>
<a href="lightning:{{.Invoice}}"><img src="{{$.QR}}" alt="QR code of the Lightning invoice" width="256" height="256"></a>
<p><code>{{.Invoice}}</code></p>
<p><a class="btn" id="open-wallet" href="lightning:{{.Invoice}}">Open in wallet</a></p>
<p id="pay-wait" hidden data-token="{{.Token}}" data-expires="{{$.ExpiresAt.Unix}}" data-claim="{{.Claim}}">
  <small id="pay-msg" role="status"></small>
</p>
<p id="wallet-box" hidden>
  <button type="button" id="webln-pay" data-invoice="{{.Invoice}}" data-token="{{.Token}}">Pay with one click</button>
  <small id="webln-msg"></small>
</p>
{{else}}
<p>Lightning payments are unavailable right now.</p>
{{end}}
</details>
{{if and .Solve (not .Auto)}}<p id="pw-start" hidden><button type="button" id="pow-go">No sats? Do the challenge instead</button> <small>about {{.Seconds}} of computing in your browser</small></p>
{{end}}{{if .Solve}}<noscript><p>The proof-of-work needs JavaScript.{{if .Auto}} You can open &ldquo;Pay with Lightning instead&rdquo; above.{{end}}</p></noscript>
{{end}}</div>
<p><small>Bots and scripts can also solve a proof-of-work puzzle instead of paying
(difficulty {{.PoW.Difficulty}}, about {{.PoW.ExpectedSeconds}} seconds on one CPU core). Details are in the <code>WWW-Authenticate</code> headers of this response.
This offer expires at {{.ExpiresAt.Format "15:04 MST"}}.</small></p>
<p><small>Protected by <a href="https://github.com/Choffolo/spikes402">Spikes402</a>.{{with .Siege}} <a href="{{.}}">See the siege in real time</a>{{end}}</small></p>
{{.Script}}
</body>
</html>
`))

// weblnJS is the only script on the 402 page. It is written as a raw
// string so the Content-Security-Policy hash matches the bytes the
// browser sees. Invoice and token are read from the button, not
// interpolated here.
const weblnJS = `(function(){
var w=window.webln,box=document.getElementById("wallet-box");
if(!box||!w||typeof w.enable!=="function"||typeof w.sendPayment!=="function")return;
box.hidden=false;
var btn=document.getElementById("webln-pay"),msg=document.getElementById("webln-msg"),busy=false,KEY="spikes402-redeemed";
function say(t,err){msg.textContent=t||"";msg.className=err?"err":""}
function fail(e){
  busy=false;btn.disabled=false;document.dispatchEvent(new Event("spikes402-payment-failed"));
  var m=(e&&(e.message||e.reason)||e||"")+"";
  say(/reject|denied|cancel|user/i.test(m)?"Payment was cancelled or the wallet was declined. You can still pay the invoice above.":(m||"Payment failed."),"err");
}
function pay(){
  if(busy)return;
  busy=true;btn.disabled=true;say("Requesting payment…");document.dispatchEvent(new Event("spikes402-payment"));
  Promise.resolve().then(function(){return w.enable()}).then(function(){return w.sendPayment(btn.getAttribute("data-invoice"))}).then(function(res){
    var preimage=((res&&(res.preimage||res.paymentPreimage))||"").toString().replace(/^0x/i,"").replace(/\s/g,"");
    if(!preimage)throw new Error("The wallet did not return a preimage.");
    return fetch(location.href,{headers:{Authorization:"L402 "+btn.getAttribute("data-token")+":"+preimage,"Spikes402-Redeem":"cookie"},credentials:"same-origin",cache:"no-store"}).then(function(r){
      if(r.status!==204)throw new Error("Payment was sent, but the page did not accept it ("+r.status+").");
      try{sessionStorage.setItem(KEY,Date.now())}catch(e){}
      location.replace(location.href);
    });
  }).catch(fail);
}
btn.addEventListener("click",pay);
var last=0;try{last=+sessionStorage.getItem(KEY)||0}catch(e){}
if(Date.now()-last<50000){say("Payment was sent, but the browser did not keep the access cookie. Allow cookies for this site and try again in a minute.",true)}
else pay();
})();`

var weblnHash = base64.StdEncoding.EncodeToString(sha256Sum([]byte(weblnJS)))

// wall.js runs the puzzle in the browser; pow-worker.js is the worker it
// starts, served by the proxy itself (see serveWorker). Both are embedded
// so the page needs nothing from outside.
var (
	//go:embed assets/wall.js
	wallJS string
	//go:embed assets/invoice.js
	invoiceJS string
	//go:embed assets/pow-worker.js
	powWorkerJS string
	//go:embed assets/logo.svg
	logoSVG string

	wallHash    = base64.StdEncoding.EncodeToString(sha256Sum([]byte(wallJS)))
	invoiceHash = base64.StdEncoding.EncodeToString(sha256Sum([]byte(invoiceJS)))

	// logoInline sits next to the wall title; logoFavicon is a data URI
	// so the icon needs no extra CSP source (img-src already allows data:).
	logoInline  = template.HTML(inlineLogo(logoSVG))
	logoFavicon = template.URL("data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(logoSVG)))
	// logoHome wraps the mark in a link to the site root. The proxy is
	// self-hosted, so this must be "/", not a hard-coded external URL.
	logoHome = template.HTML(`<a href="/" class="logo-link" aria-label="Back to the site">` + string(logoInline) + `</a>`)

	// workerSrc carries a content hash so a new release is never served
	// from an old cached copy.
	workerSrc = WorkerPath + "?v=" + hex.EncodeToString(sha256Sum([]byte(powWorkerJS))[:6])

	// pageCSP: nothing from outside, two known inline scripts, and workers
	// only from this origin.
	pageCSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'sha256-" + weblnHash + "' 'sha256-" + invoiceHash + "' 'sha256-" + wallHash +
		"'; connect-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

// ReservedPrefix is the path prefix the proxy answers itself. Nothing
// under it is subject to protect rules or forwarded to the origin.
const (
	ReservedPrefix = "/.spikes402/"
	WorkerPath     = "/.spikes402/pow-worker.js"
)

func (g *Gate) serveReserved(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case WorkerPath:
		serveWorker(w, r)
	case ClaimPath:
		g.serveClaim(w, r)
	case StatsPath:
		if g.opt.PublicStats != nil {
			g.opt.PublicStats.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	case SiegePagePath:
		if g.opt.PublicSiege != nil {
			g.opt.PublicSiege.servePage(w, r)
			return
		}
		http.NotFound(w, r)
	case SiegeJSONPath:
		if g.opt.PublicSiege != nil {
			g.opt.PublicSiege.serveJSON(w, r)
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func serveWorker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/javascript; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'")
	h.Set("Cache-Control", "public, max-age=86400")
	if r.Method == http.MethodGet {
		io.WriteString(w, powWorkerJS)
	}
}

// ldJSON is the schema.org markup Google asks for on paywalled pages: the
// page is not free, and the part behind the wall is the ".paywall" block.
// json.Marshal escapes <, > and &, so the text cannot close the script.
func ldJSON(p *Preview) template.HTML {
	type part struct {
		Type        string `json:"@type"`
		Free        bool   `json:"isAccessibleForFree"`
		CSSSelector string `json:"cssSelector"`
	}
	doc := struct {
		Context     string `json:"@context"`
		Type        string `json:"@type"`
		Name        string `json:"name,omitempty"`
		Description string `json:"description,omitempty"`
		Free        bool   `json:"isAccessibleForFree"`
		HasPart     part   `json:"hasPart"`
	}{Context: "https://schema.org", Type: "WebPage", HasPart: part{"WebPageElement", false, ".paywall"}}
	if p != nil {
		doc.Name, doc.Description = p.Title, p.Description
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return ""
	}
	return template.HTML(`<script type="application/ld+json">` + string(b) + `</script>`)
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// inlineLogo turns the standalone SVG file into a decorative inline mark
// (no XML declaration, no accessible name — the heading already has the title).
func inlineLogo(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "<?xml") {
		if i := strings.Index(s, "?>"); i >= 0 {
			s = strings.TrimSpace(s[i+2:])
		}
	}
	s = strings.Replace(s, ` role="img"`, "", 1)
	s = strings.Replace(s, ` aria-label="Spikes402"`, ` class="logo" aria-hidden="true"`, 1)
	return s
}

// satUnit is "sat" for a price of 1, and "sats" otherwise.
func satUnit(n int64) string {
	if n == 1 {
		return "sat"
	}
	return "sats"
}

// invoiceQR is a data URI of the Lightning invoice as a QR code.
// Wallets expect upper-case BOLT11 in QR codes (smaller code).
func invoiceQR(invoice string) template.URL {
	png, err := qrcode.Encode(strings.ToUpper("lightning:"+invoice), qrcode.Medium, 256)
	if err != nil {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
}

func writeHTML(w io.Writer, b challengeBody, qr template.URL, mode, siege string) {
	data := struct {
		challengeBody
		QR        template.URL
		Script    template.HTML
		LD        template.HTML
		Logo      template.HTML
		Favicon   template.URL
		SatUnit   string
		Siege     string
		Solve     bool   // the browser can solve this puzzle (browser_pow on, not Argon2id)
		Auto      bool   // the puzzle starts at once (browser_pow "auto")
		Mode      string // browser_pow: "button" or "auto"
		Seconds   string // expected time in a browser, for the button
		Tiles     template.HTML
		WorkerSrc string
		Claim     string
	}{challengeBody: b, QR: qr, LD: ldJSON(b.Preview), Logo: logoHome, Favicon: logoFavicon, SatUnit: satUnit(b.PriceSats), Siege: siege, WorkerSrc: workerSrc, Claim: ClaimPath, Tiles: pwTiles}
	var scripts string
	if mode == "" {
		mode = BrowserPoWButton
	}
	// The puzzle script goes first: it listens for "spikes402-payment", which
	// the WebLN script fires as soon as it starts paying, so the work pauses.
	if data.Solve = mode != BrowserPoWOff && b.PoW.Algorithm != pow.Argon2id; data.Solve {
		data.Mode, data.Auto = mode, mode == BrowserPoWAuto
		data.Seconds = humanSeconds(math.Exp2(float64(b.PoW.Difficulty)) / browserHashrate)
		scripts += "<script>" + wallJS + "</script>\n"
	}
	if b.L402 != nil {
		scripts += "<script>" + weblnJS + "</script>\n"
		scripts += "<script>" + invoiceJS + "</script>\n"
	}
	data.Script = template.HTML(scripts)
	page.Execute(w, data)
}

// browser_pow modes (Options.BrowserPoW). "" means BrowserPoWButton.
const (
	BrowserPoWButton = "button" // the invoice first, "No sats? Do the challenge instead"
	BrowserPoWAuto   = "auto"   // the puzzle starts at once, paying is one click away
	BrowserPoWOff    = "off"    // invoice only
)

// browserHashrate is sha256d attempts per second of a typical browser
// with its workers (about 1 million per thread, a few threads).
const browserHashrate = 2e6

// pwTiles are the squares that fill up while the browser works.
var pwTiles = template.HTML(strings.Repeat("<i></i>", 64))

// humanSeconds writes a duration roughly: "3 s", "2 min".
func humanSeconds(s float64) string {
	if s < 90 {
		return fmt.Sprintf("%.0f s", math.Max(1, s))
	}
	return fmt.Sprintf("%.0f min", s/60)
}
