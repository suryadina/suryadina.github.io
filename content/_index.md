---
title: "suryadina.com"
description: "Coffee, tea, tech, and security — field notes from Ardya (@suryadina)."
---

Security engineer by trade, perpetual learner by habit. I poke at apps until
they confess, write down what I learn, and keep a cup close — coffee to start
the day, tea to wind it down. ☕🍵

<div>
  <a class="btn-pill" href="/posts/">📝 Writings</a>
  <a class="btn-pill" href="/projects/">🧰 Projects</a>
  <a class="btn-pill" href="/tools/">🛠️ Tools</a>
  <a class="btn-pill" href="/brews/">☕ Coffee &amp; Tea</a>
  <a class="btn-pill" href="/about/">👋 About</a>
</div>

{{< rawhtml >}}
<div class="v60-game not-prose" id="v60game" aria-label="V60 pour-over mini game">
  <style>
    #v60game{--g-primary:var(--color-primary-500,245,158,11);--g-primary-d:var(--color-primary-700,180,83,9);
      max-width:430px;margin:2.5rem auto 0;border:1px solid rgba(var(--color-neutral-200),.6);
      border-radius:16px;padding:18px 18px 20px;text-align:center;
      background:rgba(var(--color-neutral-100),.5);}
    .dark #v60game{border-color:rgba(var(--color-neutral-700),.7);background:rgba(var(--color-neutral-800),.45);}
    #v60game *{box-sizing:border-box;}
    #v60game .v60-h{font-weight:700;font-size:1.05rem;margin:0 0 2px;}
    #v60game .v60-sub{font-size:.82rem;opacity:.7;margin:0 0 14px;line-height:1.4;}
    #v60game .v60-stage{display:flex;gap:16px;align-items:flex-end;justify-content:center;}
    #v60game .v60-vessel{position:relative;width:120px;height:210px;flex:0 0 auto;
      border:3px solid rgb(var(--g-primary));border-top:none;border-radius:6px 6px 30px 30px/6px 6px 70px 70px;
      overflow:hidden;background:rgba(var(--color-neutral-200),.25);}
    .dark #v60game .v60-vessel{background:rgba(var(--color-neutral-900),.5);}
    #v60game .v60-water{position:absolute;left:0;right:0;bottom:0;height:0%;
      background:linear-gradient(rgba(var(--g-primary-d),.95),rgba(60,38,20,.97));
      transition:height .05s linear;}
    #v60game .v60-water::before{content:"";position:absolute;top:0;left:0;right:0;height:5px;
      background:rgb(var(--g-primary));opacity:.9;}
    #v60game .v60-band{position:absolute;left:-3px;right:-3px;border-top:2px dashed rgb(var(--g-primary));
      border-bottom:2px dashed rgb(var(--g-primary));background:rgba(var(--g-primary),.16);pointer-events:none;}
    #v60game .v60-band b{position:absolute;right:5px;top:50%;transform:translateY(-50%);
      font-size:.6rem;font-weight:700;color:rgb(var(--g-primary));opacity:.95;}
    #v60game .v60-stream{position:absolute;top:-46px;left:50%;width:4px;height:46px;margin-left:-2px;
      background:linear-gradient(rgba(var(--g-primary),0),rgb(var(--g-primary)));border-radius:2px;
      opacity:0;transition:opacity .08s;}
    #v60game.pouring .v60-stream{opacity:.9;}
    #v60game .v60-readout{font-variant-numeric:tabular-nums;font-weight:700;font-size:1.3rem;margin-top:6px;}
    #v60game .v60-readout span{font-size:.7rem;font-weight:600;opacity:.6;}
    #v60game .v60-side{display:flex;flex-direction:column;justify-content:flex-end;gap:8px;
      width:122px;text-align:left;padding-bottom:2px;}
    #v60game .v60-phase{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;
      color:rgb(var(--g-primary));}
    #v60game .v60-target{font-size:.78rem;opacity:.82;line-height:1.4;}
    #v60game .v60-steps{display:flex;gap:5px;margin-top:2px;}
    #v60game .v60-steps i{width:9px;height:9px;border-radius:50%;border:1.5px solid rgba(var(--g-primary),.6);font-style:normal;}
    #v60game .v60-steps i.done{background:rgb(var(--g-primary));border-color:rgb(var(--g-primary));}
    #v60game .v60-msg{min-height:1.3em;font-size:.85rem;margin:12px 0 12px;line-height:1.4;}
    #v60game .v60-btn{appearance:none;cursor:pointer;user-select:none;-webkit-user-select:none;touch-action:none;
      width:100%;padding:13px;border-radius:11px;border:none;font-weight:800;font-size:1rem;
      color:#1c1610;background:rgb(var(--g-primary));transition:transform .06s,filter .15s,opacity .15s;}
    #v60game .v60-btn:hover{filter:brightness(1.06);}
    #v60game.pouring .v60-btn{transform:translateY(1px) scale(.99);filter:brightness(.92);}
    #v60game .v60-btn:disabled{opacity:.45;cursor:not-allowed;filter:none;}
    #v60game .v60-again{margin-top:10px;background:transparent;border:1px solid rgba(var(--g-primary),.6);
      color:rgb(var(--g-primary));padding:9px;border-radius:11px;font-weight:700;cursor:pointer;width:100%;display:none;}
    #v60game .v60-hint{font-size:.7rem;opacity:.5;margin-top:9px;}
    #v60game .v60-result{font-size:.95rem;font-weight:700;line-height:1.45;}
  </style>

  <p class="v60-h">☕ Brew a V60 &mdash; mini&nbsp;game</p>
  <p class="v60-sub">Pour water to each target line. <b>Hold</b> the button (or Space) to pour, release to stop. Nail the bloom, then build to 250&nbsp;g.</p>

  <div class="v60-stage">
    <div class="v60-vessel" id="v60vessel">
      <div class="v60-stream"></div>
      <div class="v60-water" id="v60water"></div>
      <div class="v60-band" id="v60band"><b id="v60bandlbl"></b></div>
    </div>
    <div class="v60-side">
      <div class="v60-phase" id="v60phase">Phase 1 &middot; Bloom</div>
      <div class="v60-target" id="v60target">Aim: ~45&nbsp;g<br>wet the grounds</div>
      <div class="v60-steps" id="v60steps"><i></i><i></i><i></i></div>
      <div class="v60-readout"><span id="v60g">0</span><span> / 250 g</span></div>
    </div>
  </div>

  <p class="v60-msg" id="v60msg">Tap &amp; hold to start the bloom.</p>
  <button class="v60-btn" id="v60btn" type="button">POUR&nbsp;💧 (hold)</button>
  <button class="v60-again" id="v60again" type="button">Brew again ↻</button>
  <p class="v60-hint">A toy. Real V60: 15 g coffee &middot; 250 g water &middot; ~2:30 total.</p>
</div>
<script>
(function(){
  var TOTAL=250;
  var PHASES=[
    {name:"Bloom",      label:"Phase 1 · Bloom",      target:18, band:8,  hint:"Aim: ~45&nbsp;g<br>wet the grounds", bloom:true},
    {name:"First pour", label:"Phase 2 · First pour", target:60, band:9,  hint:"Aim: ~150&nbsp;g<br>steady spiral"},
    {name:"Second pour",label:"Phase 3 · Top up",     target:100,band:7,  hint:"Aim: 250&nbsp;g<br>fill to the top"}
  ];
  var el=function(id){return document.getElementById(id);};
  var game=el("v60game"), water=el("v60water"), band=el("v60band"), bandlbl=el("v60bandlbl");
  var phaseEl=el("v60phase"), targetEl=el("v60target"), msg=el("v60msg"), btn=el("v60btn"), again=el("v60again");
  var gEl=el("v60g"), steps=el("v60steps").children;
  var RATE=30;
  var level=0, idx=0, pouring=false, locked=false, finished=false, blooming=false, last=0, scores=[];

  function setBand(p){
    var lo=Math.max(0,p.target-p.band), hi=Math.min(100,p.target+p.band);
    band.style.bottom=lo+"%"; band.style.height=(hi-lo)+"%"; bandlbl.textContent="target";
  }
  function loadPhase(){
    var p=PHASES[idx];
    phaseEl.textContent=p.label; targetEl.innerHTML=p.hint; setBand(p);
    msg.textContent= idx===0 ? "Tap & hold to start the bloom." : "Keep pouring — hold to the band.";
    btn.disabled=false; locked=false;
  }
  function render(){ water.style.height=level+"%"; gEl.textContent=Math.round(level/100*TOTAL); }
  function frame(ts){
    if(!last) last=ts; var dt=(ts-last)/1000; last=ts;
    if(pouring && !locked && !finished && !blooming){
      level+=RATE*dt;
      if(level>=100){ level=100; render(); endPour(true); } else render();
    }
    requestAnimationFrame(frame);
  }
  function startPour(){ if(locked||finished||blooming||btn.disabled) return; pouring=true; game.classList.add("pouring"); }
  function endPour(overflow){
    if(!pouring && !overflow) return;
    pouring=false; game.classList.remove("pouring");
    if(locked||finished||blooming) return;
    var p=PHASES[idx]; locked=true; btn.disabled=true;
    var err=Math.abs(level-p.target);
    var s=Math.max(0, Math.round(100*(1-err/(p.band*2.4))));
    if(overflow && level>=100 && p.target<100) s=Math.max(0,s-30);
    scores[idx]=s; steps[idx].className="done";
    msg.textContent = (overflow && p.target<100) ? "Whoa — overflowed! 💦" :
                      err<=p.band ? "Right in the band. 👌" :
                      level<p.target ? "A touch shy." : "A little heavy.";
    if(p.bloom){
      blooming=true; var t=3.4, b0=performance.now();
      msg.textContent="Let it bloom… 🌸 ("+t.toFixed(1)+"s)";
      var iv=setInterval(function(){
        var lft=t-((performance.now()-b0)/1000);
        if(lft<=0){ clearInterval(iv); blooming=false; nextPhase(); }
        else msg.textContent="Let it bloom… 🌸 ("+lft.toFixed(1)+"s)";
      },100);
    } else { setTimeout(nextPhase, 650); }
  }
  function nextPhase(){ idx++; if(idx>=PHASES.length){ finish(); return; } loadPhase(); }
  function finish(){
    finished=true; btn.disabled=true; btn.style.display="none"; again.style.display="block";
    var avg=Math.round(scores.reduce(function(a,b){return a+b;},0)/scores.length);
    var r;
    if(avg>=90) r="☕✨ Perfect extraction — balanced &amp; sweet. ("+avg+"/100)";
    else if(avg>=75) r="👌 Great cup — nicely brewed. ("+avg+"/100)";
    else if(avg>=55) r="☕ Drinkable, a little off-balance. ("+avg+"/100)";
    else if(avg>=35) r="😬 Bitter — over-extracted. ("+avg+"/100)";
    else r="🫠 Sour &amp; weak — give it another go. ("+avg+"/100)";
    phaseEl.textContent="Done!"; targetEl.innerHTML="Score "+avg+"/100";
    msg.innerHTML='<span class="v60-result">'+r+'</span>';
  }
  function reset(){
    level=0; idx=0; pouring=false; locked=false; finished=false; blooming=false; scores=[];
    for(var i=0;i<steps.length;i++) steps[i].className="";
    btn.style.display=""; again.style.display="none"; game.classList.remove("pouring");
    render(); loadPhase();
  }

  btn.addEventListener("pointerdown",function(e){e.preventDefault();startPour();});
  window.addEventListener("pointerup",function(){endPour(false);});
  btn.addEventListener("pointercancel",function(){endPour(false);});
  window.addEventListener("blur",function(){endPour(false);});
  window.addEventListener("keydown",function(e){ if(e.code==="Space"||e.key===" "){ e.preventDefault(); startPour(); }});
  window.addEventListener("keyup",function(e){ if(e.code==="Space"||e.key===" "){ e.preventDefault(); endPour(false); }});
  again.addEventListener("click",reset);

  reset(); requestAnimationFrame(frame);
})();
</script>
{{< /rawhtml >}}
