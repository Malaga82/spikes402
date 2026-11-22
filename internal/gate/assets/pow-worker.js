// Spikes402 proof-of-work worker (sha256d), served by the proxy at
// /.spikes402/pow-worker.js. No dependencies, no network.
//
// Finds a nonce so that SHA256(SHA256(challenge + ":" + nonce)) has at
// least `difficulty` leading zero bits, nonce written in decimal: the same
// puzzle as the Go client and pow.Params.Check. The constant part of the
// input is hashed once (midstate); each attempt costs about three SHA-256
// block compressions.
//
// In:  {challenge, difficulty, start}   (start: first nonce to try)
//      or {header, difficulty, start, end} for the Bitcoin lottery (see solveHeader)
// Out: {attempts}                       progress, every ~200 ms
//      {attempts, nonce}                solved
//      {attempts, exhausted}            lottery range done without a solution
(function () {
"use strict";
var K = new Int32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);
var IV = new Int32Array([
  0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
]);

// One SHA-256 block: w[0..15] is the message, s the state (updated).
function compress(s, w) {
  var i, a, b, t1, t2;
  for (i = 16; i < 64; i++) {
    a = w[i - 15]; b = w[i - 2];
    w[i] = (((a >>> 7 | a << 25) ^ (a >>> 18 | a << 14) ^ (a >>> 3)) + w[i - 7] +
            ((b >>> 17 | b << 15) ^ (b >>> 19 | b << 13) ^ (b >>> 10)) + w[i - 16]) | 0;
  }
  var A = s[0], B = s[1], C = s[2], D = s[3], E = s[4], F = s[5], G = s[6], H = s[7];
  for (i = 0; i < 64; i++) {
    t1 = (H + ((E >>> 6 | E << 26) ^ (E >>> 11 | E << 21) ^ (E >>> 25 | E << 7)) + ((E & F) ^ (~E & G)) + K[i] + w[i]) | 0;
    t2 = (((A >>> 2 | A << 30) ^ (A >>> 13 | A << 19) ^ (A >>> 22 | A << 10)) + ((A & B) ^ (A & C) ^ (B & C))) | 0;
    H = G; G = F; F = E; E = (D + t1) | 0; D = C; C = B; B = A; A = (t1 + t2) | 0;
  }
  s[0] = (s[0] + A) | 0; s[1] = (s[1] + B) | 0; s[2] = (s[2] + C) | 0; s[3] = (s[3] + D) | 0;
  s[4] = (s[4] + E) | 0; s[5] = (s[5] + F) | 0; s[6] = (s[6] + G) | 0; s[7] = (s[7] + H) | 0;
}

function bswap(x) { return (x >>> 24 | x >>> 8 & 0xff00 | x << 8 & 0xff0000 | x << 24) | 0; }

// Bitcoin lottery: header is a real block header without its nonce (76
// bytes, hex). Hash header + nonce (4 bytes, little-endian) twice and read
// the digest as a little-endian number, as pow.HeaderHash does.
function solveHeader(m) {
  var bits = m.difficulty | 0, n = m.start >>> 0, end = m.end >>> 0, i, h = m.header;
  var b = new Uint8Array(76);
  for (i = 0; i < 76; i++) b[i] = parseInt(h.substr(2 * i, 2), 16);
  var mid = new Int32Array(IV), w = new Int32Array(64), s = new Int32Array(8), s2 = new Int32Array(8), tw = new Int32Array(16);
  for (i = 0; i < 16; i++) w[i] = b[4 * i] << 24 | b[4 * i + 1] << 16 | b[4 * i + 2] << 8 | b[4 * i + 3];
  compress(mid, w);
  for (i = 0; i < 3; i++) tw[i] = b[64 + 4 * i] << 24 | b[65 + 4 * i] << 16 | b[66 + 4 * i] << 8 | b[67 + 4 * i];
  tw[4] = -2147483648; tw[15] = 640;
  var zw = bits >>> 5, rb = bits & 31, attempts = 0, last = Date.now();
  for (;;) {
    tw[3] = bswap(n);
    s.set(mid);
    for (i = 0; i < 16; i++) w[i] = tw[i];
    compress(s, w);
    for (i = 0; i < 8; i++) w[i] = s[i];
    w[8] = -2147483648; w[9] = 0; w[10] = 0; w[11] = 0; w[12] = 0; w[13] = 0; w[14] = 0; w[15] = 256;
    s2.set(IV);
    compress(s2, w);
    attempts++;
    var ok = true;
    for (i = 0; i < zw; i++) if (s2[7 - i] !== 0) { ok = false; break; }
    if (ok && rb && (bswap(s2[7 - zw]) >>> (32 - rb)) !== 0) ok = false;
    if (ok) { self.postMessage({ attempts: attempts, nonce: n }); return; }
    if (n === end) { self.postMessage({ attempts: attempts, exhausted: true }); return; }
    n = (n + 1) >>> 0;
    if ((attempts & 16383) === 0) {
      var now = Date.now();
      if (now - last >= 200) { last = now; self.postMessage({ attempts: attempts }); }
    }
  }
}

self.onmessage = function (e) {
  if (e.data.header) return solveHeader(e.data);
  var m = e.data, bits = m.difficulty | 0, n = m.start, i, j;
  var prefix = new TextEncoder().encode(m.challenge + ":");
  var nfull = prefix.length >>> 6;
  var mid = new Int32Array(IV), w = new Int32Array(64), s = new Int32Array(8), s2 = new Int32Array(8);
  for (j = 0; j < nfull; j++) {
    for (i = 0; i < 16; i++) {
      var o = j * 64 + i * 4;
      w[i] = prefix[o] << 24 | prefix[o + 1] << 16 | prefix[o + 2] << 8 | prefix[o + 3];
    }
    compress(mid, w);
  }
  // The rest of the prefix, the decimal nonce and the padding: one or two blocks.
  var tail = prefix.subarray(nfull * 64), tl = tail.length;
  var buf = new Uint8Array(192), tw = new Int32Array(32), nd = 0, nb = 1;
  function layout() {
    var ds = String(n), len, end, total;
    nd = ds.length;
    buf.fill(0);
    buf.set(tail, 0);
    for (var k = 0; k < nd; k++) buf[tl + k] = ds.charCodeAt(k);
    len = tl + nd;
    buf[len] = 0x80;
    nb = (len + 9 + 63) >>> 6;
    end = nb * 64;
    total = (nfull * 64 + len) * 8;
    buf[end - 4] = total >>> 24; buf[end - 3] = total >>> 16 & 255; buf[end - 2] = total >>> 8 & 255; buf[end - 1] = total & 255;
    for (var q = 0; q < nb * 16; q++) tw[q] = buf[4 * q] << 24 | buf[4 * q + 1] << 16 | buf[4 * q + 2] << 8 | buf[4 * q + 3];
  }
  layout();

  var zw = bits >>> 5, rb = bits & 31, attempts = 0, last = Date.now();
  for (;;) {
    s.set(mid);
    for (i = 0; i < 16; i++) w[i] = tw[i];
    compress(s, w);
    if (nb === 2) {
      for (i = 0; i < 16; i++) w[i] = tw[16 + i];
      compress(s, w);
    }
    for (i = 0; i < 8; i++) w[i] = s[i];
    w[8] = -2147483648; w[9] = 0; w[10] = 0; w[11] = 0; w[12] = 0; w[13] = 0; w[14] = 0; w[15] = 256;
    s2.set(IV);
    compress(s2, w);
    attempts++;

    var ok = true;
    for (i = 0; i < zw; i++) if (s2[i] !== 0) { ok = false; break; }
    if (ok && rb && (s2[zw] >>> (32 - rb)) !== 0) ok = false;
    if (ok) { self.postMessage({ attempts: attempts, nonce: n }); return; }

    n++;
    var p = tl + nd - 1;
    while (p >= tl && buf[p] === 57) { buf[p] = 48; p--; }
    if (p < tl) layout();               // 9, 99, 999 ... gained a digit
    else {
      buf[p]++;
      for (j = p >> 2; j <= (tl + nd - 1) >> 2; j++) tw[j] = buf[4 * j] << 24 | buf[4 * j + 1] << 16 | buf[4 * j + 2] << 8 | buf[4 * j + 3];
    }
    if ((attempts & 16383) === 0) {
      var now = Date.now();
      if (now - last >= 200) { last = now; self.postMessage({ attempts: attempts }); }
    }
  }
};
})();
