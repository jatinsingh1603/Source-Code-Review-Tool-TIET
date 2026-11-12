// Synthetic sample for the engine conformance cases. Not real code.
import * as child from "child_process";

interface Request {
  query: { name: string };
}

export function handler(req: Request): RegExp {
  const name: string = req.query.name;
  child.exec("ls " + name);
  const pattern = new RegExp(name);
  eval(name);
  (document.getElementById("greeting") as HTMLElement).innerHTML = name;
  return pattern;
}
