import { useEffect, useRef } from "react"

/**
 * Campo de partículas estilo "constelación": puntos lima que derivan lento y se
 * unen con líneas cuando están cerca. Canvas dep-free, DPR-aware, respeta
 * prefers-reduced-motion (dibuja un frame estático). Pensado para ir detrás del
 * contenido del hero (position:absolute, pointer-events:none).
 */
export function Particles({ className = "" }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const cv0 = ref.current
    const par0 = cv0?.parentElement
    const g0 = cv0?.getContext("2d")
    if (!cv0 || !par0 || !g0) return
    // re-bind a consts no-nulos: las funciones de abajo están hoisted y TS no
    // propaga el narrowing del guard hacia ellas si los binds son los originales.
    const cv = cv0
    const par = par0
    const g = g0

    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    const COUNT = 48
    const LINK = 130
    const LIME = "163,230,53"

    let w = 0
    let h = 0
    let raf = 0
    type P = { x: number; y: number; vx: number; vy: number }
    let pts: P[] = []
    const rnd = (a: number, b: number) => a + Math.random() * (b - a)

    function resize() {
      const r = par.getBoundingClientRect()
      w = Math.max(1, r.width)
      h = Math.max(1, r.height)
      cv.width = Math.round(w * dpr)
      cv.height = Math.round(h * dpr)
      cv.style.width = `${w}px`
      cv.style.height = `${h}px`
      g.setTransform(dpr, 0, 0, dpr, 0, 0)
    }

    function seed() {
      pts = Array.from({ length: COUNT }, () => ({
        x: rnd(0, w),
        y: rnd(0, h),
        vx: rnd(-0.22, 0.22),
        vy: rnd(-0.22, 0.22),
      }))
    }

    function draw(step: boolean) {
      g.clearRect(0, 0, w, h)
      if (step) {
        for (const p of pts) {
          p.x += p.vx
          p.y += p.vy
          if (p.x <= 0 || p.x >= w) p.vx *= -1
          if (p.y <= 0 || p.y >= h) p.vy *= -1
        }
      }
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const dx = pts[i].x - pts[j].x
          const dy = pts[i].y - pts[j].y
          const d = Math.hypot(dx, dy)
          if (d < LINK) {
            g.strokeStyle = `rgba(${LIME},${(1 - d / LINK) * 0.16})`
            g.lineWidth = 1
            g.beginPath()
            g.moveTo(pts[i].x, pts[i].y)
            g.lineTo(pts[j].x, pts[j].y)
            g.stroke()
          }
        }
      }
      g.fillStyle = `rgba(${LIME},0.7)`
      for (const p of pts) {
        g.beginPath()
        g.arc(p.x, p.y, 1.4, 0, Math.PI * 2)
        g.fill()
      }
    }

    function loop() {
      draw(true)
      raf = requestAnimationFrame(loop)
    }

    resize()
    seed()
    if (reduce) {
      draw(false)
    } else {
      raf = requestAnimationFrame(loop)
    }

    const onResize = () => {
      resize()
      seed()
      if (reduce) draw(false)
    }
    window.addEventListener("resize", onResize)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener("resize", onResize)
    }
  }, [])

  return (
    <canvas
      ref={ref}
      aria-hidden
      className={className}
      style={{ position: "absolute", inset: 0, pointerEvents: "none" }}
    />
  )
}
