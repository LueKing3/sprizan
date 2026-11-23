/**
 * SPRIZAN — Dragon Guardian & Volumetric Neck Smoke Shader
 * Implements continuous domain-warped fractal Brownian motion smoke in raw WebGL.
 * Zero external libraries. 100% additive, responsive, and performance-optimized.
 */

(function () {
  'use strict';

  // Vertex shader for full-screen quad
  const VS_SOURCE = `
    attribute vec2 a_position;
    varying vec2 v_uv;
    void main() {
      v_uv = (a_position + 1.0) * 0.5;
      gl_Position = vec4(a_position, 0.0, 1.0);
    }
  `;

  // Fragment shader for continuous volumetric smoke
  const FS_SOURCE = `
    precision highp float;
    varying vec2 v_uv;
    uniform vec2 u_resolution;
    uniform float u_time;
    uniform float u_opacity;
    uniform float u_speed;

    // 2D pseudo-random hash
    float hash(vec2 p) {
      p = fract(p * vec2(123.34, 456.21));
      p += dot(p, p + 45.32);
      return fract(p.x * p.y);
    }

    // Bilinear value noise
    float noise(vec2 p) {
      vec2 i = floor(p);
      vec2 f = fract(p);
      vec2 u = f * f * (3.0 - 2.0 * f);
      return mix(
        mix(hash(i + vec2(0.0, 0.0)), hash(i + vec2(1.0, 0.0)), u.x),
        mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), u.x),
        u.y
      );
    }

    // 5-octave Fractal Brownian Motion with 2D rotation
    float fbm(vec2 p) {
      float v = 0.0;
      float a = 0.5;
      mat2 rot = mat2(0.80, 0.60, -0.60, 0.80);
      for (int i = 0; i < 5; i++) {
        v += a * noise(p);
        p = rot * p * 2.02;
        a *= 0.5;
      }
      return v;
    }

    // Ridged noise for sharp energy filaments along plume edges
    float ridged(vec2 p) {
      float n = noise(p);
      return 1.0 - abs(2.0 * n - 1.0);
    }

    void main() {
      vec2 uv = v_uv;
      float t = u_time * 0.032 * u_speed;

      // Coordinate scaling for smoke ribbons: smoke emerges near bottom (y ~ 0.15) and rises up
      vec2 p = uv * vec2(3.6, 3.2);
      p.y -= t * 2.0;
      p.x += sin(t * 0.75 + uv.y * 2.6) * 0.32;

      // Domain warping (fbm warped twice: q then r, then f(p + 3.2*r))
      vec2 q = vec2(
        fbm(p + vec2(0.0, 0.0)),
        fbm(p + vec2(5.2, 1.3) + vec2(t * 0.22, -t * 0.42))
      );

      vec2 r = vec2(
        fbm(p + 3.6 * q + vec2(1.7, 9.2) + vec2(-t * 0.28, t * 0.12)),
        fbm(p + 3.6 * q + vec2(8.3, 2.8) + vec2(t * 0.16, -t * 0.24))
      );

      float f = fbm(p + 3.4 * r);

      // Fine filaments along the curling wisps
      float rf = ridged(p * 2.8 + 2.2 * r);
      rf = pow(clamp(rf, 0.0, 1.0), 2.4);

      // Neck Plume mask: emitted around base (x=0.5, y=0.15), rising, swaying and expanding
      float h = clamp((uv.y - 0.10) / 0.88, 0.0, 1.0);
      float spineX = 0.50 + sin(t * 1.15 + h * 3.14159) * (0.075 * h);
      float spread = 0.19 + h * 0.44;
      float dx = abs(uv.x - spineX) / spread;
      float plumeMask = exp(-dx * dx * 3.2);

      // Smooth vertical dissolution: soft entry at neck, soft dissipation at top
      float vertFade = smoothstep(0.06, 0.24, uv.y) * smoothstep(0.98, 0.62, uv.y);

      // Feather all canvas borders so no rectangle is ever visible
      vec2 edgeDist = min(uv, 1.0 - uv);
      float edgeFeather = smoothstep(0.0, 0.18, edgeDist.x) * smoothstep(0.0, 0.18, edgeDist.y);

      // Combined smoke density
      float density = (f * 0.72 + rf * 0.46) * plumeMask * vertFade * edgeFeather;

      // Secondary soft ambient volume haze
      float haze = fbm(uv * 2.2 + vec2(t * 0.12, -t * 0.35)) * plumeMask * vertFade * edgeFeather * 0.26;
      float totalD = clamp(density + haze, 0.0, 1.0);

      // Color ramp by density:
      // black -> deep crimson (#3a0303) -> rich red (#b01212) -> scarlet (#ff2a3b) -> bright orange highlight (#ff6040)
      vec3 colDeep = vec3(0.227, 0.012, 0.012);  // #3a0303
      vec3 colMid  = vec3(0.690, 0.071, 0.071);  // #b01212
      vec3 colHot  = vec3(1.0, 0.165, 0.231);    // #ff2a3b
      vec3 colHighlight = vec3(1.0, 0.42, 0.24); // #ff6b3d

      vec3 color = mix(colDeep, colMid, smoothstep(0.08, 0.38, totalD));
      color = mix(color, colHot, smoothstep(0.38, 0.74, totalD));
      color = mix(color, colHighlight, smoothstep(0.74, 1.0, totalD) * rf);

      float alpha = smoothstep(0.05, 0.68, totalD) * 0.55 * u_opacity;

      // Premultiplied alpha for mix-blend-mode: screen
      gl_FragColor = vec4(color * alpha, alpha);
    }
  `;

  let gl = null;
  let program = null;
  let animId = null;
  let startTime = performance.now();
  let isRunning = false;
  let isReducedMotion = false;
  let targetParallaxX = 0;
  let targetParallaxY = 0;
  let currentParallaxX = 0;
  let currentParallaxY = 0;

  function createShader(glCtx, type, source) {
    const shader = glCtx.createShader(type);
    glCtx.shaderSource(shader, source);
    glCtx.compileShader(shader);
    if (!glCtx.getShaderParameter(shader, glCtx.COMPILE_STATUS)) {
      console.warn('[SPRIZAN Dragon] Shader compile failed:', glCtx.getShaderInfoLog(shader));
      glCtx.deleteShader(shader);
      return null;
    }
    return shader;
  }

  function initWebGL(canvas) {
    const opts = {
      alpha: true,
      premultipliedAlpha: true,
      antialias: false,
      depth: false,
      stencil: false,
      powerPreference: 'low-power',
    };

    let glCtx = canvas.getContext('webgl', opts) || canvas.getContext('experimental-webgl', opts);
    if (!glCtx) {
      console.warn('[SPRIZAN Dragon] WebGL unavailable, activating fallback gradient.');
      activateFallback(canvas);
      return false;
    }

    const vs = createShader(glCtx, glCtx.VERTEX_SHADER, VS_SOURCE);
    const fs = createShader(glCtx, glCtx.FRAGMENT_SHADER, FS_SOURCE);
    if (!vs || !fs) {
      activateFallback(canvas);
      return false;
    }

    const prg = glCtx.createProgram();
    glCtx.attachShader(prg, vs);
    glCtx.attachShader(prg, fs);
    glCtx.linkProgram(prg);

    if (!glCtx.getProgramParameter(prg, glCtx.LINK_STATUS)) {
      console.warn('[SPRIZAN Dragon] Program link failed:', glCtx.getProgramInfoLog(prg));
      activateFallback(canvas);
      return false;
    }

    gl = glCtx;
    program = prg;

    // Full screen quad buffer
    const positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]),
      gl.STATIC_DRAW
    );

    const posAttr = gl.getAttribLocation(program, 'a_position');
    gl.enableVertexAttribArray(posAttr);
    gl.vertexAttribPointer(posAttr, 2, gl.FLOAT, false, 0, 0);

    return true;
  }

  function activateFallback(canvas) {
    if (!canvas || !canvas.parentElement) return;
    const fallback = document.createElement('div');
    fallback.className = 'dragon-smoke-fallback';
    canvas.parentElement.appendChild(fallback);
    canvas.style.display = 'none';
  }

  function resizeCanvas(canvas) {
    if (!canvas || !gl) return;
    const rect = canvas.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;

    // Render at 0.5x internal resolution with DPR capped at 1.5 for optimal performance
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    const targetW = Math.max(1, Math.floor(rect.width * dpr * 0.5));
    const targetH = Math.max(1, Math.floor(rect.height * dpr * 0.5));

    if (canvas.width !== targetW || canvas.height !== targetH) {
      canvas.width = targetW;
      canvas.height = targetH;
      gl.viewport(0, 0, targetW, targetH);
    }
  }

  function updateDragonPosition() {
    const orb = document.querySelector('.scan-orb-wrapper');
    const theater = document.querySelector('.scan-theater');
    const dragon = document.getElementById('dragon-layer');
    if (!orb || !theater || !dragon) return;

    const orbRect = orb.getBoundingClientRect();
    const theaterRect = theater.getBoundingClientRect();

    if (theaterRect.width > 0 && orbRect.width > 0) {
      const cx = orbRect.left + orbRect.width / 2 - theaterRect.left;
      const cy = orbRect.top + orbRect.height / 2 - theaterRect.top;
      dragon.style.left = `${cx.toFixed(2)}px`;
      dragon.style.top = `${cy.toFixed(2)}px`;
    }
  }

  function render(time) {
    const scanStage = document.getElementById('scan-stage');
    const canvas = document.getElementById('dragon-smoke-canvas');
    const dragon = document.getElementById('dragon-layer');

    // Check visibility
    const isStageVisible = scanStage && !scanStage.classList.contains('hidden') && !document.hidden;
    if (!isStageVisible) {
      isRunning = false;
      return;
    }

    if (gl && program && canvas) {
      resizeCanvas(canvas);

      gl.useProgram(program);

      // Pass uniforms
      const uRes = gl.getUniformLocation(program, 'u_resolution');
      const uTime = gl.getUniformLocation(program, 'u_time');
      const uOpacity = gl.getUniformLocation(program, 'u_opacity');
      const uSpeed = gl.getUniformLocation(program, 'u_speed');

      gl.uniform2f(uRes, canvas.width, canvas.height);
      gl.uniform1f(uTime, (time - startTime) * 0.001);

      // Read CSS tunables if customized
      const computed = getComputedStyle(document.documentElement);
      const opacityVal = parseFloat(computed.getPropertyValue('--smoke-opacity')) || 0.85;
      const speedVal = parseFloat(computed.getPropertyValue('--smoke-speed')) || 1.0;

      gl.uniform1f(uOpacity, opacityVal);
      gl.uniform1f(uSpeed, speedVal);

      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.drawArrays(gl.TRIANGLES, 0, 6);
    }

    // Apply gentle mouse parallax (max 6px, smoothed) if motion not reduced
    if (!isReducedMotion && dragon) {
      currentParallaxX += (targetParallaxX - currentParallaxX) * 0.06;
      currentParallaxY += (targetParallaxY - currentParallaxY) * 0.06;
      dragon.style.transform = `translate(calc(-50% + ${currentParallaxX.toFixed(2)}px), calc(-50% + ${currentParallaxY.toFixed(2)}px))`;
    }

    if (isReducedMotion) {
      isRunning = false; // Render single static frame and pause
      return;
    }

    animId = requestAnimationFrame(render);
  }

  function startAnimation() {
    if (isRunning) return;
    isRunning = true;
    updateDragonPosition();
    animId = requestAnimationFrame(render);
  }

  function stopAnimation() {
    isRunning = false;
    if (animId) {
      cancelAnimationFrame(animId);
      animId = null;
    }
  }

  function setup() {
    const canvas = document.getElementById('dragon-smoke-canvas');
    const dragon = document.getElementById('dragon-layer');
    const scanStage = document.getElementById('scan-stage');
    const theater = document.querySelector('.scan-theater');

    if (!dragon) return;

    // Check accessibility reduced motion preference
    const mediaQuery = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)');
    isReducedMotion = mediaQuery ? mediaQuery.matches : false;
    if (mediaQuery) {
      mediaQuery.addEventListener('change', (e) => {
        isReducedMotion = e.matches;
        if (isReducedMotion) {
          stopAnimation();
          render(performance.now()); // static frame
        } else {
          startAnimation();
        }
      });
    }

    // Initialize WebGL
    if (canvas) {
      initWebGL(canvas);

      canvas.addEventListener('webglcontextlost', (e) => {
        e.preventDefault();
        stopAnimation();
      });

      canvas.addEventListener('webglcontextrestored', () => {
        initWebGL(canvas);
        startAnimation();
      });
    }

    // Parallax listener (clamped to max 6px)
    window.addEventListener('mousemove', (e) => {
      if (isReducedMotion) return;
      const nx = e.clientX / window.innerWidth - 0.5;
      const ny = e.clientY / window.innerHeight - 0.5;
      targetParallaxX = nx * 12; // +/- 6px
      targetParallaxY = ny * 12; // +/- 6px
    }, { passive: true });

    // Handle visibility changes (tab switch)
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        stopAnimation();
      } else {
        const isVisible = scanStage && !scanStage.classList.contains('hidden');
        if (isVisible) startAnimation();
      }
    });

    // Observer for scan stage class changes (.hidden added/removed)
    if (scanStage) {
      const observer = new MutationObserver(() => {
        const isVisible = !scanStage.classList.contains('hidden');
        if (isVisible) {
          updateDragonPosition();
          dragon.classList.add('is-visible');
          startAnimation();
        } else {
          dragon.classList.remove('is-visible');
          stopAnimation();
        }
      });
      observer.observe(scanStage, { attributes: true, attributeFilter: ['class', 'style'] });
    }

    // IntersectionObserver to pause when theater scrolled off screen
    if (theater && window.IntersectionObserver) {
      const io = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const isVisible = scanStage && !scanStage.classList.contains('hidden');
            if (isVisible) startAnimation();
          } else {
            stopAnimation();
          }
        });
      }, { threshold: 0.05 });
      io.observe(theater);
    }

    // Window resize
    window.addEventListener('resize', () => {
      updateDragonPosition();
      if (canvas) resizeCanvas(canvas);
    }, { passive: true });

    // Initial setup
    updateDragonPosition();
    if (scanStage && !scanStage.classList.contains('hidden')) {
      dragon.classList.add('is-visible');
      startAnimation();
    }
  }

  // Self-initialize on DOMContentLoaded or immediate if already loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setup);
  } else {
    setup();
  }
})();
