// Siege drawing shared by the admin dashboard and the public siege page.
// Plain JS, no dependencies. Text goes in with textContent, never as HTML.
"use strict";

window.SiegeArt = (function () {
  // One colour per outcome group: paid, proof-of-work, stopped at the
  // 402 ("held") and repelled.
  const GROUP = { paid: "paid", "pow-solved": "pow", free: "pow", challenged: "held",
    rejected: "repelled", "rate-limited": "repelled", busy: "repelled", blocked: "repelled" };
  const COLOR = { paid: "#ffc83d", pow: "#00e5ff", held: "#9aa3c7", repelled: "#ff4d6d" };

  // A visitor walks from the left to the wall, then passes the gate into
  // the site or fades at the wall (repelled ones drift back). Names show
  // on hover, or next to the dot when only a few are on screen.
  const SVGNS = "http://www.w3.org/2000/svg";
  const WALL_X = 610, GATE_Y = 205, MAX_SPRITES = 60, LABEL_BELOW = 6;
  const ease = (t) => (t < 0 ? 0 : t > 1 ? 1 : 1 - Math.pow(1 - t, 2));

  // create draws into the <g> element layer; spawn adds one dot, frame
  // moves them all (call it from requestAnimationFrame).
  function create(layer) {
    let sprites = [];
    function spawn(group, name, tip) {
      if (!COLOR[group]) group = "held";
      if (sprites.length >= MAX_SPRITES) sprites.shift().g.remove();
      const g = document.createElementNS(SVGNS, "g"); g.setAttribute("class", "sprite");
      const c = document.createElementNS(SVGNS, "circle"); c.setAttribute("r", 6); c.setAttribute("fill", COLOR[group]);
      const title = document.createElementNS(SVGNS, "title"); title.textContent = tip || "";
      const label = document.createElementNS(SVGNS, "text"); label.setAttribute("x", 10); label.setAttribute("y", 4);
      label.textContent = name || "";
      g.append(c, title, label);
      layer.append(g);
      const y0 = 40 + Math.random() * 320;
      sprites.push({ g, label, group, t0: performance.now(), x0: 20 + Math.random() * 60, y0,
        ty: group === "paid" || group === "pow" ? GATE_Y + (Math.random() * 30 - 15) : y0 });
    }
    function frame(now) {
      const few = sprites.length <= LABEL_BELOW;
      sprites = sprites.filter((s) => {
        const t = now - s.t0, walk = 2600, after = t - walk;
        let x, y = s.ty, op = 1;
        if (after < 0) { const k = ease(t / walk); x = s.x0 + (WALL_X - s.x0) * k; y = s.y0 + (s.ty - s.y0) * k; }
        else if (s.group === "paid" || s.group === "pow") {
          const k = ease(after / 1800); x = WALL_X + (860 - WALL_X) * k; y = s.ty + (240 - s.ty) * k; op = 1 - Math.max(0, (after - 1000) / 800);
        } else {
          const k = ease(after / 1500); x = WALL_X - (s.group === "repelled" ? 80 * k : 0); op = 1 - k;
        }
        s.label.style.display = few ? "" : "none";
        s.g.setAttribute("transform", `translate(${x.toFixed(1)},${y.toFixed(1)})`);
        s.g.setAttribute("opacity", Math.max(0, op).toFixed(2));
        if (op <= 0) { s.g.remove(); return false; }
        return true;
      });
    }
    return { spawn, frame };
  }

  return { GROUP, COLOR, create };
})();
