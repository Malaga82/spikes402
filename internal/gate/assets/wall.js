(function(){
var box=document.getElementById("pow-box");
if(!box||typeof Worker!=="function")return;
var challenge=box.getAttribute("data-challenge"),bits=+box.getAttribute("data-difficulty"),src=box.getAttribute("data-worker"),header=box.getAttribute("data-header");
if(header)challenge=box.getAttribute("data-lottery");// Bitcoin lottery: same work, on a real block header
var go=document.getElementById("pow-go"),bar=document.getElementById("pow-bar"),stats=document.getElementById("pow-stats"),msg=document.getElementById("pow-msg");
var expected=Math.pow(2,bits),n=Math.max(1,Math.min(navigator.hardwareConcurrency||2,8)),workers=[],counts=[],t0=0,running=false;
box.hidden=false;
function fmt(x){return Math.round(x).toLocaleString("en-US")}
function dur(x){return x<90?Math.round(x)+" s":Math.round(x/60)+" min"}
function say(t,err){msg.textContent=t||"";msg.className=err?"err":""}
function stop(){running=false;workers.forEach(function(w){w.terminate()});workers=[];go.textContent="Solve the puzzle"}
function show(){
  var a=counts.reduce(function(s,c){return s+c},0),t=(Date.now()-t0)/1000,rate=t>0?a/t:0;
  bar.value=Math.min(a/expected,1);
  var line=fmt(a)+" of about "+fmt(expected)+" attempts \u00b7 "+fmt(rate)+" hashes/s \u00b7 "+t.toFixed(1)+" s \u00b7 "+n+" thread"+(n>1?"s":"");
  if(t>=1&&rate>0){
    var left=Math.max(expected-a,0)/rate;
    line+=left>0?" \u00b7 about "+dur(left)+" left":" \u00b7 almost there";
    if(expected/rate>120)say("On this device the puzzle takes about "+dur(expected/rate)+". Paying with the extension or a wallet is much faster.");
  }
  stats.textContent=line;
}
function done(nonce){
  stop();show();say("Solved. Unlocking\u2026");
  fetch(location.href,{headers:{Authorization:"PoW "+challenge+":"+nonce,"Spikes402-Redeem":"cookie"},credentials:"same-origin",cache:"no-store"}).then(function(r){
    if(r.status!==204)throw new Error("The page did not accept the solution ("+r.status+"). Reload and try again.");
    location.replace(location.href);
  }).catch(function(e){say(e.message||"Could not unlock the page.",true)});
}
function start(){
  running=true;counts=[];t0=Date.now();bar.hidden=false;go.textContent="Cancel";say("");
  for(var i=0;i<n;i++)(function(i){
    var w=new Worker(src);workers.push(w);counts[i]=0;
    w.onmessage=function(e){
      if(!running)return;
      counts[i]=e.data.attempts;
      if(e.data.nonce!==undefined)done(e.data.nonce);
      else if(e.data.exhausted){stop();say("No solution in this block header. Reload for a new puzzle.",true)}
      else show();
    };
    w.onerror=function(){if(running){stop();say("The browser could not start the puzzle worker.",true)}};
    var span=Math.floor(4294967296/n);// lottery nonces are 32-bit: split them between the workers
    w.postMessage(header?{header:header,difficulty:bits,start:i*span,end:i===n-1?4294967295:(i+1)*span-1}:{challenge:challenge,difficulty:bits,start:i*1099511627776});
  })(i);
}
go.addEventListener("click",function(){if(running)stop();else start()});
})();