/** Reset input/VT modes left by the old shell without RIS, which discards
 * Ghostty's retained history. Only local terminal output; never SSH input. */
export const RECONNECT_TERMINAL_OUTPUT =
  "\x18\x1b[?2026l" + // Abort a partial sequence and synchronized output.
  "\x1b[?1049l\x1b[?1047l\x1b[?47l" + // Leave alternate-screen applications.
  "\x1b[0m\x1b[r\x1b[?6l\x1b[?1l\x1b[?7h\x1b[4l\x1b[20l\x1b>" +
  "\x1b(B\x1b)B\x0f\x1b[?25h\x1b[?2004l" +
  "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1016l" +
  "\x1b[<99u\x1b[>0u\x1b]8;;\x1b\\" +
  "\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\\x1b[0 q" +
  "\x1b[999B\r\n\x1b[2m── Reconnecting ──\x1b[0m\r\n";
