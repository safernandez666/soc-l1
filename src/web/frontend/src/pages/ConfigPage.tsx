import { useEffect, useMemo, useState } from "react"

import { api, type ConfigField, type ConfigSection, type ConfigUpdate } from "@/lib/api"
import { useFetch } from "@/lib/useFetch"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"

type FormValues = Record<string, string | boolean>

// Valor inicial del form para un campo. Los secretos arrancan vacíos (write-only):
// vacío = "no cambiar"; el placeholder muestra si ya está seteado.
function initialValue(f: ConfigField): string | boolean {
  if (f.kind === "secret") return ""
  if (f.kind === "bool") return Boolean(f.value)
  return f.value == null ? "" : String(f.value)
}

function seedSection(section: ConfigSection): FormValues {
  const out: FormValues = {}
  for (const f of section.fields) out[f.name] = initialValue(f)
  return out
}

export function ConfigPage() {
  const [reloadKey, setReloadKey] = useState(0)
  const state = useFetch(() => api.config(), [reloadKey])

  if (state.kind === "loading") {
    return (
      <div className="grid gap-6 md:grid-cols-[220px_1fr]">
        <Skeleton className="h-64 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    )
  }
  if (state.kind === "error") {
    return (
      <div className="rounded-md border border-destructive/40 bg-destructive/10 p-4 text-sm">
        No se pudo cargar la configuración: {state.message}
      </div>
    )
  }

  return (
    <ConfigView
      sections={state.data.sections}
      onSaved={() => setReloadKey((k) => k + 1)}
    />
  )
}

function ConfigView({
  sections,
  onSaved,
}: {
  sections: ConfigSection[]
  onSaved: () => void
}) {
  const [activeKey, setActiveKey] = useState(sections[0]?.key ?? "")
  const active = useMemo(
    () => sections.find((s) => s.key === activeKey) ?? sections[0],
    [sections, activeKey],
  )

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-semibold">Configuración</h1>
        <p className="text-sm text-muted-foreground">
          Settings operativos del SOC-L1. Se guardan en el servidor y se aplican en
          caliente — los secretos solo se escriben, nunca se muestran.
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-[220px_1fr]">
        <nav className="flex flex-row flex-wrap gap-1 md:flex-col">
          {sections.map((s) => (
            <button
              key={s.key}
              type="button"
              onClick={() => setActiveKey(s.key)}
              className={`rounded-md px-3 py-2 text-left text-sm transition-colors ${
                s.key === active?.key
                  ? "bg-secondary font-medium text-foreground"
                  : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground"
              }`}
            >
              {s.title}
            </button>
          ))}
        </nav>

        {active && (
          <SectionForm key={active.key} section={active} onSaved={onSaved} />
        )}
      </div>
    </div>
  )
}

function SectionForm({
  section,
  onSaved,
}: {
  section: ConfigSection
  onSaved: () => void
}) {
  const [values, setValues] = useState<FormValues>(() => seedSection(section))
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null)

  // Re-seed si cambia la sección (la key del componente ya lo fuerza, pero por las dudas).
  useEffect(() => {
    setValues(seedSection(section))
    setMsg(null)
  }, [section])

  function setField(name: string, v: string | boolean) {
    setValues((prev) => ({ ...prev, [name]: v }))
    setMsg(null)
  }

  function buildUpdates(): ConfigUpdate {
    const updates: ConfigUpdate = {}
    for (const f of section.fields) {
      const v = values[f.name]
      if (f.kind === "secret") {
        if (typeof v === "string" && v.trim() !== "") updates[f.name] = v
      } else if (f.kind === "bool") {
        if (v !== Boolean(f.value)) updates[f.name] = v as boolean
      } else {
        const original = f.value == null ? "" : String(f.value)
        if (String(v) !== original) updates[f.name] = v as string
      }
    }
    return updates
  }

  async function onSave() {
    const updates = buildUpdates()
    if (Object.keys(updates).length === 0) {
      setMsg({ kind: "ok", text: "No hay cambios para guardar." })
      return
    }
    setSaving(true)
    setMsg(null)
    try {
      const res = await api.saveConfig(updates)
      setMsg({ kind: "ok", text: `Guardado: ${res.applied.join(", ")}` })
      onSaved()
    } catch (e) {
      setMsg({
        kind: "err",
        text: e instanceof Error ? e.message : "Error al guardar",
      })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="rounded-lg border border-border bg-card p-6">
      <div className="mb-5">
        <h2 className="text-base font-semibold">{section.title}</h2>
      </div>

      <div className="space-y-5">
        {section.fields.map((f) => (
          <Field
            key={f.name}
            field={f}
            value={values[f.name]}
            onChange={(v) => setField(f.name, v)}
          />
        ))}
      </div>

      <div className="mt-6 flex items-center gap-3 border-t border-border pt-4">
        <Button onClick={onSave} disabled={saving}>
          {saving ? "Guardando…" : "Guardar"}
        </Button>
        {msg && (
          <span
            className={`text-sm ${
              msg.kind === "ok" ? "text-muted-foreground" : "text-destructive"
            }`}
          >
            {msg.text}
          </span>
        )}
      </div>
    </div>
  )
}

function Field({
  field: f,
  value,
  onChange,
}: {
  field: ConfigField
  value: string | boolean
  onChange: (v: string | boolean) => void
}) {
  if (f.kind === "bool") {
    return (
      <div className="flex items-center justify-between gap-4">
        <div>
          <Label htmlFor={f.name}>{f.label}</Label>
          {f.help && <p className="text-xs text-muted-foreground">{f.help}</p>}
        </div>
        <Toggle
          id={f.name}
          checked={Boolean(value)}
          onChange={(c) => onChange(c)}
        />
      </div>
    )
  }

  return (
    <div className="space-y-1.5">
      <Label htmlFor={f.name}>{f.label}</Label>
      {f.kind === "secret" ? (
        <Input
          id={f.name}
          type="password"
          autoComplete="new-password"
          placeholder={f.set ? `${f.hint} (seteado — dejá vacío para no cambiar)` : "no configurado"}
          value={value as string}
          onChange={(e) => onChange(e.target.value)}
        />
      ) : f.options && f.options.length > 0 ? (
        <select
          id={f.name}
          value={value as string}
          onChange={(e) => onChange(e.target.value)}
          className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        >
          {f.options.map((o) => (
            <option key={o} value={o} className="bg-background text-foreground">
              {o}
            </option>
          ))}
        </select>
      ) : (
        <Input
          id={f.name}
          type={f.kind === "int" ? "number" : "text"}
          inputMode={f.kind === "int" ? "numeric" : undefined}
          value={value as string}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
      {f.help && <p className="text-xs text-muted-foreground">{f.help}</p>}
    </div>
  )
}

function Toggle({
  id,
  checked,
  onChange,
}: {
  id: string
  checked: boolean
  onChange: (c: boolean) => void
}) {
  return (
    <button
      id={id}
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring ${
        checked ? "bg-primary" : "bg-input"
      }`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
          checked ? "translate-x-4" : "translate-x-0.5"
        }`}
      />
    </button>
  )
}
