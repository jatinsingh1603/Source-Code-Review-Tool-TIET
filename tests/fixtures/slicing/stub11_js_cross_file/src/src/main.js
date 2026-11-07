import { build } from "./util";

export function start(opts) {
  const config = build(opts, 5);
  return config;
}
