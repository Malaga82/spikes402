(function(){
// The 402 page's proof-of-work (browser_pow). "button": the invoice comes
// first and "No sats? Do the challenge instead" starts the puzzle; "auto":
// the puzzle starts at once. Either way, while it runs the page reads "One
// moment" and the invoice folds into "Pay N sats with Lightning instead".
// With the Bitcoin lottery the puzzle is a real block header; the ordinary
// sha256d challenge is the fallback.
var box=document.getElementById("pow-box");
if(!box||typeof Worker!=="function")return;
var $=function(id){return document.getElementById(id)};
var D=box.dataset,src=D.worker,bits=+D.difficulty,mode=D.mode;
var pay=$("pay"),go=$("pow-go"),run=$("pw-run"),title=$("pw-title"),intro=$("pw-intro");
var tiles=[].slice.call(box.querySelectorAll(".pw-grid i")),order=tiles.map(function(_,i){return i});
for(var i=order.length-1;i>0;i--){var j=Math.floor(Math.random()*(i+1)),t=order[i];order[i]=order[j];order[j]=t}
var n=Math.max(1,Math.min(navigator.hardwareConcurrency||2,8)),workers=[],counts=[],ended=0,t0=0,timer=0,best="",phase="",busy=false,done=false;
if(go)$("pw-start").hidden=false;
function say(t,err){$("pw-status").textContent=t;$("pw-status").className=err?"err":""}
function fmt(x){return Math.round(x).toLocaleString("en-US")}
function stop(){workers.forEach(function(w){w.terminate()});workers=[];ended=0}
function show(){
  var a=counts.reduce(function(s,c){return s+c},0),secs=(Date.now()-t0)/1000;
  $("pw-tries").textContent=fmt(a);
  $("pw-rate").textContent=secs>0.3&&a?fmt(a/secs/1000)+" kH/s":"–";
  // Expected share of the work done; finding the answer is luck, so this is an estimate.
  var lit=Math.min(tiles.length-1,Math.floor((1-Math.exp(-a/Math.pow(2,bits)))*tiles.length));
  order.forEach(function(k,m){tiles[k].className=m<lit?"on":""});
}
function bestHash(h){
  if(!h||(best&&h>=best))return;
  best=h;var z=h.match(/^0*/)[0].length;
  $("pw-zeros").textContent=h.slice(0,z);$("pw-rest").textContent=h.slice(z);
}
function fail(why){stop();clearInterval(timer);busy=false;say(why+" Reload the page to try again"+(pay?", or pay with Lightning.":"."),true)}
function pause(){
  if(!busy||done)return;
  stop();clearInterval(timer);busy=false;say("Paused while you pay with Lightning.");
}
function submit(token,nonce){
  if(done||!busy)return;
  done=true;stop();clearInterval(timer);
  tiles.forEach(function(t){t.className="on"});
  say("Done, opening the page…");
  fetch(location.href,{headers:{Authorization:"PoW "+token+":"+nonce,"Spikes402-Redeem":"cookie"},credentials:"same-origin",cache:"no-store"}).then(function(r){
    if(r.status===204){location.replace(location.href);return}
    done=false;
    if(phase==="bitcoin"){busy=true;timer=setInterval(show,200);return work("sha256d")}// the pool job may have expired: the ordinary puzzle still works
    throw new Error("The server did not accept the answer ("+r.status+").");
  }).catch(function(e){done=false;fail(e.message||"Network error.")});
}
function work(kind){
  stop();phase=kind;
  var lottery=kind==="bitcoin",token=lottery?D.lottery:D.challenge;
  $("pw-note-lottery").hidden=!lottery;$("pw-note-sha").hidden=lottery;
  $("pw-what").textContent=lottery?"Bitcoin block header":"double SHA-256";
  counts=[];best="";t0=Date.now();say("Computing…");
  var span=Math.floor(4294967296/n);// lottery nonces are 32-bit: split them between the workers
  for(var k=0;k<n;k++)(function(k){
    var w=new Worker(src);workers.push(w);counts[k]=0;
    w.onmessage=function(e){
      var m=e.data;
      if(!busy||done||phase!==kind)return;
      counts[k]=m.attempts;bestHash(m.hash);
      if(m.nonce!==undefined)submit(token,m.nonce);
      else if(m.exhausted&&++ended>=workers.length)work("sha256d");
    };
    w.onerror=function(){if(busy&&!done)fail("The puzzle could not start.")};
    w.postMessage(lottery?{header:D.header,difficulty:bits,start:k*span,end:k===n-1?4294967295:(k+1)*span-1}:{challenge:token,difficulty:bits,start:k*1099511627776});
  })(k);
}
function start(){
  if(busy||done)return;
  busy=true;
  if(go)$("pw-start").hidden=true;
  run.hidden=false;
  if(title)title.textContent="One moment";
  if(intro)intro.hidden=false;
  if(pay&&pay.open){pay.open=false;pay.querySelector("summary").hidden=false}
  timer=setInterval(show,200);
  work(D.header?"bitcoin":"sha256d");
}
document.addEventListener("spikes402-payment",pause);
if(pay)pay.addEventListener("toggle",function(){if(pay.open)pause();else if(!done&&phase)start()});
if(mode==="auto")start();else if(go)go.addEventListener("click",start);
})();
