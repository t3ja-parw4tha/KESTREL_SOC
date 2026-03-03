const TECHNIQUE_ID_PATTERN = /^T\d{4}(\.\d{3})?$/i

export function formatTechniqueId(id: string): string {
  return id.trim().toUpperCase()
}

export function getMitreUrl(techniqueId: string): string {
  const clean = techniqueId.trim().toUpperCase()
  if (!TECHNIQUE_ID_PATTERN.test(clean)) {
    return ''
  }
  const base = 'https://attack.mitre.org/techniques'
  const path = clean.replace(/\./g, '/')
  return `${base}/${path}/`
}
