/** The backend's key slot name rule (`slot_rules::valid_slot_name`), which key names in the library follow too. */
export function isValidSlotName(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name) && !/\.pub$/i.test(name);
}
