export function build({ mode = "fast", level: lvl = 2 } = {}, size = 10) {
  return { mode, lvl, size };
}
