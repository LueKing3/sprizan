/**
 * SPRIZAN — Dragon Guardian Layer v2
 * WebGL dragon texture with flow-warp + flame-flicker + brightness-wave,
 * multi-emitter volumetric smoke, 2D embers, debug overlay.
 * Zero external dependencies. Plain vanilla JS + raw WebGL.
 */
(function () {
  'use strict';

  /* ═══════════════════════════════════════════════════════════
     CONSTANTS — dragon.png circle-fit measurements (1200×896)
     ═══════════════════════════════════════════════════════════ */
  const ART_W = 1200, ART_H = 896;
  // Circle void centre & radius measured by least-squares fit
  const VOID_CX = 620, VOID_CY = 430, VOID_R = 135;
  const VOID_CX_F = VOID_CX / ART_W;   // 0.5167
  const VOID_CY_F = VOID_CY / ART_H;   // 0.4799

  // Eye position (art px)
  const EYE_AX = 643, EYE_AY = 160;

  // Smoke emitter positions (art px)
  const EMITTERS = [
    { ax: 380, ay: 180, strength: 1.0,  dir: [-0.25, -1.0], label: 'E1-neck' },
    { ax: 120, ay: 380, strength: 0.60, dir: [-0.90, -0.45], label: 'E2-left-coil' },
    { ax: 140, ay: 640, strength: 0.50, dir: [-0.75, -0.65], label: 'E3-tail' },
    { ax: 880, ay: 440, strength: 0.40, dir: [ 0.85, -0.50], label: 'E4-right-wisp' },
  ];

  // Head/jaw exclusion zone for flow-warp (art px, ellipse)
  const HEAD_CX = 640, HEAD_CY = 185, HEAD_RX = 210, HEAD_RY = 150;

  /* ═══════════════════════════
     SHARED GLSL SNIPPETS
     ═══════════════════════════ */
  const GLSL_NOISE = `
    float hash(vec2 p) {
      p = fract(p * vec2(123.34, 456.21));
      p += dot(p, p + 45.32);
      return fract(p.x * p.y);
    }
    float noise(vec2 p) {
      vec2 i = floor(p), f = fract(p);
      vec2 u = f*f*(3.0-2.0*f);
      return mix(mix(hash(i),hash(i+vec2(1,0)),u.x),
                 mix(hash(i+vec2(0,1)),hash(i+vec2(1,1)),u.x),u.y);
    }
    float fbm(vec2 p) {
      float v=0.0, a=0.5;
      mat2 rot = mat2(0.80,0.60,-0.60,0.80);
      for(int i=0;i<5;i++){v+=a*noise(p);p=rot*p*2.02;a*=0.5;}
      return v;
    }
    vec2 curlNoise(vec2 p) {
      const float e = 0.05;
      float n1 = noise(vec2(p.x, p.y + e));
      float n2 = noise(vec2(p.x, p.y - e));
      float n3 = noise(vec2(p.x + e, p.y));
      float n4 = noise(vec2(p.x - e, p.y));
      return vec2((n1 - n2) / (2.0 * e), -(n3 - n4) / (2.0 * e));
    }
    float ridged(vec2 p) {
      return 1.0 - abs(noise(p) * 2.0 - 1.0);
    }
  `;

  /* ═══════════════════════════════════
     VERTEX SHADER
     Maps a_pos [-1..1] to v_uv [0..1]
     v_uv.x: 0 (left) -> 1 (right)
     v_uv.y: 0 (top)  -> 1 (bottom)
     ═══════════════════════════════════ */
  const SHARED_VS = `
    attribute vec2 a_pos;
    varying vec2 v_uv;
    void main(){
      v_uv = vec2((a_pos.x + 1.0) * 0.5, (1.0 - a_pos.y) * 0.5);
      gl_Position = vec4(a_pos, 0.0, 1.0);
    }
  `;

  /* ═══════════════════════════════════
     DRAGON TEXTURE SHADER (flow-warp)
     ═══════════════════════════════════ */
  const DRAGON_FS = `
    precision highp float;
    varying vec2 v_uv;
    uniform sampler2D u_tex;
    uniform float u_time;
    uniform float u_warp;
    uniform float u_pulse;
    uniform vec2 u_headCenter;
    uniform vec2 u_headRadii;
    uniform vec2 u_voidCenter;
    uniform vec2 u_eyeUV;
    uniform float u_aspect;
    ${GLSL_NOISE}

    void main(){
      float t = u_time;
      vec2 uv = v_uv;

      // ── Head exclusion weight: 0 inside head ellipse, 1 on body ──
      vec2 hd = (uv - u_headCenter) / u_headRadii;
      float headDist = length(hd);
      float warpWeight = smoothstep(0.7, 1.35, headDist);

      // ── Flow-warp: curl noise displaces texture ──
      vec2 curl = curlNoise(uv * 3.2 + t * 0.07);
      uv += curl * u_warp * warpWeight;

      // ── Sample texture ──
      vec4 tex = texture2D(u_tex, uv);

      // ── Flame flicker on bright scales and wisps ──
      float luma = max(tex.r, max(tex.g, tex.b));
      float flickerMask = smoothstep(0.12, 0.38, luma);
      float flicker = 1.0 + 0.22 * (fbm(v_uv * 6.5 + t * 0.28) - 0.5);
      tex.rgb *= mix(1.0, flicker, flickerMask);

      // ── Brightness energy wave around void ──
      vec2 toVoid = (v_uv - u_voidCenter) * vec2(u_aspect, 1.0);
      float angle = atan(toVoid.y, toVoid.x);
      float wave = 0.5 + 0.5 * sin(angle * 1.5 - t * 0.7);
      float bodyMask = smoothstep(0.12, 0.38, length(toVoid));
      tex.rgb *= 1.0 + u_pulse * wave * bodyMask * flickerMask;

      // ── Eye additive glow ──
      float eyeDist = length((v_uv - u_eyeUV) * vec2(u_aspect, 1.0));
      float eyeGlow = exp(-eyeDist * eyeDist * 7500.0);
      float eyePulse = 0.7 + 0.3 * sin(t * 1.9);
      tex.rgb += vec3(1.0, 0.88, 0.65) * eyeGlow * eyePulse * 0.75;

      // ── Soft edge feathering so crest and edges never cut sharply ──
      float edgeFadeX = smoothstep(0.0, 0.04, v_uv.x) * smoothstep(1.0, 0.96, v_uv.x);
      float edgeFadeY = smoothstep(0.0, 0.07, v_uv.y) * smoothstep(1.0, 0.93, v_uv.y);
      float feather = edgeFadeX * edgeFadeY;

      tex.rgb *= feather;

      // Premultiplied alpha: transparent outside dragon pixels
      float alpha = smoothstep(0.015, 0.08, luma) * feather;
      gl_FragColor = vec4(tex.rgb, alpha);
    }
  `;

  /* ═══════════════════════════════════
     SMOKE SHADER (Full Theater Coverage)
     ═══════════════════════════════════ */
  const SMOKE_FS = `
    precision highp float;
    varying vec2 v_uv;
    uniform float u_time;
    uniform float u_opacity;
    uniform float u_speed;
    uniform float u_hazeOpacity;
    uniform float u_aspect;
    uniform vec4 u_em1; // xy=pos in uv, z=strength, w=unused
    uniform vec4 u_em2;
    uniform vec4 u_em3;
    uniform vec4 u_em4;
    uniform vec2 u_voidCenter;
    uniform float u_voidR;
    ${GLSL_NOISE}

    float plume(vec2 uv, vec2 emPos, vec2 emDir, float strength, float t, float aspect){
      vec2 d = (uv - emPos) * vec2(aspect, 1.0);
      vec2 dir = normalize(emDir * vec2(aspect, 1.0));
      float along = dot(d, dir);
      float across = length(d - along * dir);
      float h = max(0.0, along);
      float spread = 0.05 + h * 0.65;
      float core = exp(-across * across / (spread * spread * 2.0));
      float dist = length(d);
      float fade = exp(-dist * 1.6) * strength;

      vec2 p = uv * 3.5 * vec2(aspect, 1.0) + dir * t * 0.6;
      vec2 q = vec2(fbm(p), fbm(p + vec2(5.2, 1.3) + t * 0.2));
      vec2 r = vec2(fbm(p + 3.0 * q + vec2(1.7, 9.2) - t * 0.1), fbm(p + 3.0 * q + vec2(8.3, 2.8) + t * 0.12));
      float f = fbm(p + 2.8 * r);
      float rf = pow(clamp(ridged(p * 2.2 + 1.8 * r), 0.0, 1.0), 2.0);
      return (f * 0.65 + rf * 0.45) * core * fade;
    }

    void main(){
      float t = u_time * 0.05 * u_speed;
      vec2 uv = v_uv;

      // Accumulate 4 plumes
      float density = 0.0;
      density += plume(uv, u_em1.xy, vec2(-0.25, -1.0), u_em1.z, t, u_aspect);
      density += plume(uv, u_em2.xy, vec2(-0.90, -0.45), u_em2.z, t, u_aspect);
      density += plume(uv, u_em3.xy, vec2(-0.75, -0.65), u_em3.z, t, u_aspect);
      density += plume(uv, u_em4.xy, vec2( 0.85, -0.50), u_em4.z, t, u_aspect);

      // Ambient atmospheric red haze
      float haze = fbm(uv * 2.5 * vec2(u_aspect, 1.0) + vec2(t * 0.08, -t * 0.15)) * u_hazeOpacity;
      float totalD = clamp(density + haze, 0.0, 1.0);

      // Void mask: smoothly fade out smoke inside the orb core
      float vd = length((uv - u_voidCenter) * vec2(u_aspect, 1.0));
      float voidMask = smoothstep(u_voidR * 0.65, u_voidR * 1.15, vd);
      totalD *= voidMask;

      // Soft feathering at theater edges
      vec2 ed = min(uv, 1.0 - uv);
      float ef = smoothstep(0.0, 0.08, ed.x) * smoothstep(0.0, 0.08, ed.y);
      totalD *= ef;

      // Blood-red / crimson / scarlet flame color ramp
      vec3 c1 = vec3(0.35, 0.02, 0.02);
      vec3 c2 = vec3(0.85, 0.08, 0.08);
      vec3 c3 = vec3(1.00, 0.25, 0.16);
      vec3 c4 = vec3(1.00, 0.78, 0.65);
      vec3 col = mix(c1, c2, smoothstep(0.03, 0.25, totalD));
      col = mix(col, c3, smoothstep(0.25, 0.60, totalD));
      col = mix(col, c4, smoothstep(0.60, 0.95, totalD) * 0.65);

      float alpha = smoothstep(0.02, 0.45, totalD) * u_opacity;
      gl_FragColor = vec4(col * alpha, alpha);
    }
  `;

  /* ═══════════════════════════
     STATE
     ═══════════════════════════ */
  let dragonGL = null, dragonPrg = null, dragonTex = null;
  let smokeGL = null, smokePrg = null;
  let animId = null, t0 = performance.now(), running = false;
  let reducedMotion = false;
  let layerEl, artCanvas, smokeCanvas, emberCanvas, eyeEl;
  let orbW = 440, orbCx = 0, orbCy = 0;
  let theaterW = 0, theaterH = 0;
  let artW = 0, artH = 0, artL = 0, artT = 0;
  let emitters_theater = [];
  let debugMode = false;

  /* ═══════════════════════════
     EMBER SYSTEM (2D Canvas)
     ═══════════════════════════ */
  const embers = [];
  function initEmbers(count) {
    embers.length = 0;
    for (let i = 0; i < count; i++) {
      embers.push(createEmber(true));
    }
  }

  function createEmber(initial) {
    // 60% spawn near dragon body/emitters, 40% spawn across theater width
    let x, y;
    if (Math.random() < 0.6 && emitters_theater.length > 0) {
      const em = emitters_theater[Math.floor(Math.random() * emitters_theater.length)];
      x = em.x + (Math.random() - 0.5) * 80;
      y = em.y + (Math.random() - 0.5) * 60;
    } else {
      x = Math.random() * (theaterW || 900);
      y = Math.random() * (theaterH || 600);
    }

    const life = 3.0 + Math.random() * 3.5;
    return {
      x,
      y,
      vx: (Math.random() - 0.5) * 0.3,
      vy: -(0.35 + Math.random() * 0.65),
      swayFreq: 1.5 + Math.random() * 2.0,
      swayAmp: 0.4 + Math.random() * 0.6,
      swayPhase: Math.random() * Math.PI * 2,
      size: 1.4 + Math.random() * 2.0,
      age: initial ? Math.random() * life : 0,
      life,
      baseAlpha: 0.4 + Math.random() * 0.5,
      twinkleFreq: 2.0 + Math.random() * 4.0,
    };
  }

  function updateAndDrawEmbers(ctx, dt, time) {
    if (!ctx || theaterW < 1 || theaterH < 1) return;
    ctx.clearRect(0, 0, theaterW, theaterH);

    const voidR = orbW * 0.26;

    for (let i = 0; i < embers.length; i++) {
      const p = embers[i];
      p.age += dt;
      if (p.age >= p.life || p.y < -20 || p.x < -20 || p.x > theaterW + 20) {
        embers[i] = createEmber(false);
        continue;
      }

      // Physics
      p.x += (p.vx + Math.sin(time * p.swayFreq + p.swayPhase) * p.swayAmp) * dt * 60;
      p.y += p.vy * dt * 60;

      // Smoothstep life fade
      const progress = p.age / p.life;
      const fadeIn = Math.min(1, progress * 4.0);
      const fadeOut = Math.min(1, (1 - progress) * 2.5);
      const twinkle = 0.8 + 0.2 * Math.sin(time * p.twinkleFreq);

      // Void mask
      const dx = p.x - orbCx;
      const dy = p.y - orbCy;
      const dist = Math.hypot(dx, dy);
      let voidFade = 1.0;
      if (dist < voidR) {
        voidFade = Math.max(0, (dist - voidR * 0.6) / (voidR * 0.4));
      }

      const alpha = p.baseAlpha * fadeIn * fadeOut * twinkle * voidFade;
      if (alpha <= 0.01) continue;

      ctx.save();
      ctx.globalAlpha = alpha;
      const grad = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.size * 2);
      grad.addColorStop(0, '#ffffff');
      grad.addColorStop(0.3, '#ffaa66');
      grad.addColorStop(0.7, '#ff2a3b');
      grad.addColorStop(1, 'transparent');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size * 2, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    }
  }

  /* ═══════════════════════════
     WEBGL UTILITIES
     ═══════════════════════════ */
  function mkShader(gl, type, src) {
    const s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
      console.warn('[DragonLayer] Shader error:', gl.getShaderInfoLog(s));
      gl.deleteShader(s);
      return null;
    }
    return s;
  }

  function mkProgram(gl, vsSrc, fsSrc) {
    const vs = mkShader(gl, gl.VERTEX_SHADER, vsSrc);
    const fs = mkShader(gl, gl.FRAGMENT_SHADER, fsSrc);
    if (!vs || !fs) return null;
    const prg = gl.createProgram();
    gl.attachShader(prg, vs);
    gl.attachShader(prg, fs);
    gl.linkProgram(prg);
    if (!gl.getProgramParameter(prg, gl.LINK_STATUS)) {
      console.warn('[DragonLayer] Link error:', gl.getProgramInfoLog(prg));
      return null;
    }
    return prg;
  }

  function mkQuad(gl) {
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]),
      gl.STATIC_DRAW
    );
    return buf;
  }

  function getGL(canvas, alpha) {
    const opts = { alpha, premultipliedAlpha: true, antialias: false, depth: false, stencil: false, powerPreference: 'low-power' };
    return canvas.getContext('webgl', opts) || canvas.getContext('experimental-webgl', opts);
  }

  function sizeCanvas(canvas, gl, scale) {
    const r = canvas.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    const w = Math.max(1, Math.floor(r.width * dpr * scale));
    const h = Math.max(1, Math.floor(r.height * dpr * scale));
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w;
      canvas.height = h;
      gl.viewport(0, 0, w, h);
    }
  }

  /* ═══════════════════════════
     LAYOUT: Position & size dragon layer and canvases
     ═══════════════════════════ */
  function layout() {
    const orb = document.querySelector('.scan-orb-wrapper');
    const theater = document.querySelector('.scan-theater');
    const timeline = document.querySelector('.scan-timeline-container');
    if (!orb || !theater || !layerEl || !artCanvas) return;

    const tR = theater.getBoundingClientRect();
    const oR = orb.getBoundingClientRect();
    if (tR.width < 1 || oR.width < 1) return;

    theaterW = tR.width;
    theaterH = tR.height;
    orbW = oR.width;

    // Orb centre in theater-local coordinates
    orbCx = oR.left + oR.width / 2 - tR.left;
    orbCy = oR.top + oR.height / 2 - tR.top;

    // Sizing so crest clears top of theater by at least 16px
    const panelTop = 16;
    const availAbove = Math.max(120, orbCy - panelTop);
    const maxH_top = availAbove / VOID_CY_F;

    // Bottom of artwork tail stays above timeline top
    const timelineR = timeline ? timeline.getBoundingClientRect() : null;
    const panelBot = timelineR ? (timelineR.top - tR.top - 12) : (tR.height - 40);
    const availBelow = Math.max(120, panelBot - orbCy);
    const maxH_bot = availBelow / (1.0 - VOID_CY_F);

    // Width bounded by theater with breathing margin
    const maxW = tR.width - 24;
    const maxH_width = maxW * (ART_H / ART_W);

    let baseH = Math.min(maxH_top, maxH_bot, maxH_width);

    // CSS tunables
    const cs = getComputedStyle(document.documentElement);
    const userScale = parseFloat(cs.getPropertyValue('--dragon-scale')) || 1.0;
    const userDx = parseFloat(cs.getPropertyValue('--dragon-x')) || 0;
    const userDy = parseFloat(cs.getPropertyValue('--dragon-y')) || 0;

    artH = baseH * userScale;
    artW = artH * (ART_W / ART_H);

    // Concentric alignment: void centre matches orb centre
    artL = orbCx - VOID_CX_F * artW + userDx;
    artT = orbCy - VOID_CY_F * artH + userDy;

    artCanvas.style.left = artL.toFixed(1) + 'px';
    artCanvas.style.top = artT.toFixed(1) + 'px';
    artCanvas.style.width = artW.toFixed(1) + 'px';
    artCanvas.style.height = artH.toFixed(1) + 'px';

    // Breathing transform-origin = orb centre relative to artCanvas
    const originX = orbCx - artL;
    const originY = orbCy - artT;
    artCanvas.style.transformOrigin = `${originX.toFixed(1)}px ${originY.toFixed(1)}px`;

    // Eye glow position
    if (eyeEl) {
      const eyeX = artL + (EYE_AX / ART_W) * artW;
      const eyeY = artT + (EYE_AY / ART_H) * artH;
      eyeEl.style.left = eyeX.toFixed(1) + 'px';
      eyeEl.style.top = eyeY.toFixed(1) + 'px';
    }

    // Emitters in theater coordinates (for full-theater smoke canvas)
    emitters_theater = EMITTERS.map(e => ({
      x: artL + (e.ax / ART_W) * artW,
      y: artT + (e.ay / ART_H) * artH,
      ux: (artL + (e.ax / ART_W) * artW) / theaterW,
      uy: (artT + (e.ay / ART_H) * artH) / theaterH,
      strength: e.strength,
      dir: e.dir,
      label: e.label,
    }));

    // Size 2D ember canvas
    if (emberCanvas) {
      const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      const ew = Math.floor(theaterW * dpr);
      const eh = Math.floor(theaterH * dpr);
      if (emberCanvas.width !== ew || emberCanvas.height !== eh) {
        emberCanvas.width = ew;
        emberCanvas.height = eh;
        const ctx = emberCanvas.getContext('2d');
        if (ctx) ctx.scale(dpr, dpr);
      }
    }

    if (debugMode) updateDebugDots();
  }

  /* ═══════════════════════════
     DEBUG OVERLAY (?fxdebug=1)
     ═══════════════════════════ */
  function updateDebugDots() {
    let overlay = layerEl.querySelector('.dragon-debug-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.className = 'dragon-debug-overlay';
      layerEl.appendChild(overlay);
    }
    overlay.innerHTML = '';

    // Cyan dot: orb centre
    const dotOrb = document.createElement('div');
    dotOrb.className = 'dragon-debug-dot orb-center';
    dotOrb.style.left = orbCx.toFixed(1) + 'px';
    dotOrb.style.top = orbCy.toFixed(1) + 'px';
    dotOrb.title = `Orb Centre (${orbCx.toFixed(0)}, ${orbCy.toFixed(0)})`;
    overlay.appendChild(dotOrb);

    // Magenta dot: artwork circle centre
    const artVoidX = artL + VOID_CX_F * artW;
    const artVoidY = artT + VOID_CY_F * artH;
    const dotArt = document.createElement('div');
    dotArt.className = 'dragon-debug-dot art-center';
    dotArt.style.left = artVoidX.toFixed(1) + 'px';
    dotArt.style.top = artVoidY.toFixed(1) + 'px';
    dotArt.title = `Art Void Centre (${artVoidX.toFixed(0)}, ${artVoidY.toFixed(0)})`;
    overlay.appendChild(dotArt);

    // Yellow dot: eye
    if (eyeEl) {
      const dotEye = document.createElement('div');
      dotEye.className = 'dragon-debug-dot eye-dot';
      dotEye.style.left = eyeEl.style.left;
      dotEye.style.top = eyeEl.style.top;
      dotEye.title = 'Eye';
      overlay.appendChild(dotEye);
    }

    // Green dashed dots: smoke emitters
    emitters_theater.forEach(em => {
      const dotEm = document.createElement('div');
      dotEm.className = 'dragon-debug-dot emitter-dot';
      dotEm.style.left = em.x.toFixed(1) + 'px';
      dotEm.style.top = em.y.toFixed(1) + 'px';
      dotEm.title = `${em.label} (${em.x.toFixed(0)}, ${em.y.toFixed(0)})`;
      overlay.appendChild(dotEm);
    });
  }

  /* ═══════════════════════════
     DRAGON TEXTURE WEBGL
     ═══════════════════════════ */
  function initDragonGL() {
    if (!artCanvas) return false;
    const gl = getGL(artCanvas, true); // True alpha
    if (!gl) return false;
    const prg = mkProgram(gl, SHARED_VS, DRAGON_FS);
    if (!prg) return false;

    dragonGL = gl;
    dragonPrg = prg;
    mkQuad(gl);
    const posAttr = gl.getAttribLocation(prg, 'a_pos');
    gl.enableVertexAttribArray(posAttr);
    gl.vertexAttribPointer(posAttr, 2, gl.FLOAT, false, 0, 0);

    gl.enable(gl.BLEND);
    gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);

    // Load texture
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.src = './dragon.png';
    img.onload = () => {
      const tex = gl.createTexture();
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, img);
      dragonTex = tex;
    };
    img.onerror = () => {
      console.warn('[DragonLayer] dragon.png failed to load, using CSS fallback');
      activateFallback();
    };

    return true;
  }

  function renderDragon(time) {
    if (!dragonGL || !dragonPrg || !dragonTex) return;
    const gl = dragonGL;
    sizeCanvas(artCanvas, gl, 1.0);

    gl.useProgram(dragonPrg);

    const cs = getComputedStyle(document.documentElement);
    const warp = parseFloat(cs.getPropertyValue('--dragon-warp')) || 0.016;
    const pulse = parseFloat(cs.getPropertyValue('--dragon-pulse')) || 0.20;

    gl.uniform1f(gl.getUniformLocation(dragonPrg, 'u_time'), time);
    gl.uniform1f(gl.getUniformLocation(dragonPrg, 'u_warp'), warp);
    gl.uniform1f(gl.getUniformLocation(dragonPrg, 'u_pulse'), pulse);
    gl.uniform2f(gl.getUniformLocation(dragonPrg, 'u_headCenter'), HEAD_CX / ART_W, HEAD_CY / ART_H);
    gl.uniform2f(gl.getUniformLocation(dragonPrg, 'u_headRadii'), HEAD_RX / ART_W, HEAD_RY / ART_H);
    gl.uniform2f(gl.getUniformLocation(dragonPrg, 'u_voidCenter'), VOID_CX_F, VOID_CY_F);
    gl.uniform2f(gl.getUniformLocation(dragonPrg, 'u_eyeUV'), EYE_AX / ART_W, EYE_AY / ART_H);
    gl.uniform1f(gl.getUniformLocation(dragonPrg, 'u_aspect'), ART_W / ART_H);

    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, dragonTex);
    gl.uniform1i(gl.getUniformLocation(dragonPrg, 'u_tex'), 0);

    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLES, 0, 6);
  }

  /* ═══════════════════════════
     SMOKE WEBGL (Full Theater)
     ═══════════════════════════ */
  function initSmokeGL() {
    if (!smokeCanvas) return false;
    const gl = getGL(smokeCanvas, true);
    if (!gl) return false;
    const prg = mkProgram(gl, SHARED_VS, SMOKE_FS);
    if (!prg) return false;

    smokeGL = gl;
    smokePrg = prg;
    mkQuad(gl);
    const posAttr = gl.getAttribLocation(prg, 'a_pos');
    gl.enableVertexAttribArray(posAttr);
    gl.vertexAttribPointer(posAttr, 2, gl.FLOAT, false, 0, 0);

    gl.enable(gl.BLEND);
    gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);

    return true;
  }

  function renderSmoke(time) {
    if (!smokeGL || !smokePrg || theaterW < 1 || theaterH < 1) return;
    const gl = smokeGL;
    sizeCanvas(smokeCanvas, gl, 0.5); // Half resolution for high fps

    gl.useProgram(smokePrg);

    const cs = getComputedStyle(document.documentElement);
    const opacity = parseFloat(cs.getPropertyValue('--smoke-opacity')) || 0.90;
    const speed = parseFloat(cs.getPropertyValue('--smoke-speed')) || 1.0;
    const hazeOpacity = parseFloat(cs.getPropertyValue('--haze-opacity')) || 0.12;

    gl.uniform1f(gl.getUniformLocation(smokePrg, 'u_time'), time);
    gl.uniform1f(gl.getUniformLocation(smokePrg, 'u_opacity'), opacity);
    gl.uniform1f(gl.getUniformLocation(smokePrg, 'u_speed'), speed);
    gl.uniform1f(gl.getUniformLocation(smokePrg, 'u_hazeOpacity'), hazeOpacity);
    gl.uniform1f(gl.getUniformLocation(smokePrg, 'u_aspect'), theaterW / theaterH);

    // Emitters in theater UV
    const e1 = emitters_theater[0] || { ux: 0.5, uy: 0.3, strength: 1.0 };
    const e2 = emitters_theater[1] || { ux: 0.3, uy: 0.5, strength: 0.7 };
    const e3 = emitters_theater[2] || { ux: 0.3, uy: 0.7, strength: 0.7 };
    const e4 = emitters_theater[3] || { ux: 0.7, uy: 0.5, strength: 0.7 };

    gl.uniform4f(gl.getUniformLocation(smokePrg, 'u_em1'), e1.ux, e1.uy, e1.strength, 0);
    gl.uniform4f(gl.getUniformLocation(smokePrg, 'u_em2'), e2.ux, e2.uy, e2.strength, 0);
    gl.uniform4f(gl.getUniformLocation(smokePrg, 'u_em3'), e3.ux, e3.uy, e3.strength, 0);
    gl.uniform4f(gl.getUniformLocation(smokePrg, 'u_em4'), e4.ux, e4.uy, e4.strength, 0);

    // Void mask in theater UV
    gl.uniform2f(gl.getUniformLocation(smokePrg, 'u_voidCenter'), orbCx / theaterW, orbCy / theaterH);
    gl.uniform1f(gl.getUniformLocation(smokePrg, 'u_voidR'), (orbW * 0.26) / theaterW);

    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLES, 0, 6);
  }

  /* ═══════════════════════════
     FALLBACK: Static Image Mode
     ═══════════════════════════ */
  function activateFallback() {
    if (!layerEl) return;
    const existing = layerEl.querySelector('.dragon-artwork-fallback');
    if (existing) return;
    const img = document.createElement('img');
    img.src = './dragon.png';
    img.alt = 'SPRIZAN Dragon Guardian';
    img.className = 'dragon-artwork-fallback';
    img.style.left = artCanvas ? artCanvas.style.left : '0px';
    img.style.top = artCanvas ? artCanvas.style.top : '0px';
    img.style.width = artCanvas ? artCanvas.style.width : '100%';
    img.style.height = artCanvas ? artCanvas.style.height : '100%';
    layerEl.insertBefore(img, artCanvas);
    if (artCanvas) artCanvas.style.display = 'none';
  }

  /* ═══════════════════════════
     ANIMATION LOOP (60fps)
     ═══════════════════════════ */
  let lastTime = performance.now();
  function loop(now) {
    if (!running) return;
    animId = requestAnimationFrame(loop);

    const time = (now - t0) * 0.001;
    const dt = Math.min(0.1, (now - lastTime) * 0.001);
    lastTime = now;

    if (reducedMotion) {
      renderDragon(0);
      renderSmoke(0);
      return;
    }

    // Gentle breathing scale on dragon art canvas (6s period)
    const breathe = 1.0 + 0.018 * Math.sin(time * (Math.PI * 2 / 6.0));
    if (artCanvas) {
      artCanvas.style.transform = `scale(${breathe.toFixed(4)})`;
    }

    renderDragon(time);
    renderSmoke(time);

    // Embers
    if (emberCanvas) {
      const ctx = emberCanvas.getContext('2d');
      updateAndDrawEmbers(ctx, dt, time);
    }
  }

  function start() {
    if (running) return;
    running = true;
    lastTime = performance.now();
    animId = requestAnimationFrame(loop);
  }

  function stop() {
    running = false;
    if (animId) {
      cancelAnimationFrame(animId);
      animId = null;
    }
  }

  /* ═══════════════════════════
     INITIALIZATION & LIFECYCLE
     ═══════════════════════════ */
  function init() {
    layerEl = document.getElementById('dragon-layer');
    if (!layerEl) return;

    artCanvas = layerEl.querySelector('.dragon-art-canvas');
    smokeCanvas = layerEl.querySelector('.dragon-smoke-canvas');
    emberCanvas = layerEl.querySelector('.dragon-ember-canvas');
    eyeEl = layerEl.querySelector('.dragon-eye-glow');

    // Check debug mode (?fxdebug=1)
    try {
      const params = new URLSearchParams(window.location.search);
      debugMode = params.get('fxdebug') === '1';
    } catch (_) { debugMode = false; }

    // Check reduced motion
    const mql = window.matchMedia('(prefers-reduced-motion: reduce)');
    reducedMotion = mql.matches;
    mql.addEventListener('change', e => { reducedMotion = e.matches; });

    // Initialize WebGL contexts
    const dragonOK = initDragonGL();
    const smokeOK = initSmokeGL();
    if (!dragonOK) activateFallback();

    // Initialize embers
    const cs = getComputedStyle(document.documentElement);
    const emberCount = parseInt(cs.getPropertyValue('--ember-count'), 10) || 60;
    initEmbers(emberCount);

    // Layout
    layout();
    window.addEventListener('resize', layout);

    // Watch for scan stage visibility
    const stage = document.getElementById('scan-stage');
    if (stage) {
      const isVisible = () => !stage.classList.contains('hidden') && getComputedStyle(stage).display !== 'none';
      if (isVisible()) {
        layerEl.classList.add('is-visible');
        start();
      }
      const obs = new MutationObserver(() => {
        if (isVisible()) {
          layerEl.classList.add('is-visible');
          layout();
          start();
        } else {
          layerEl.classList.remove('is-visible');
          stop();
        }
      });
      obs.observe(stage, { attributes: true, attributeFilter: ['class', 'style'] });
    } else {
      layerEl.classList.add('is-visible');
      start();
    }

    // Tab visibility handling
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) stop();
      else if (stage && !stage.classList.contains('hidden')) start();
    });

    // WebGL context loss recovery
    if (artCanvas) {
      artCanvas.addEventListener('webglcontextlost', (e) => {
        e.preventDefault();
        stop();
      });
      artCanvas.addEventListener('webglcontextrestored', () => {
        initDragonGL();
        start();
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
