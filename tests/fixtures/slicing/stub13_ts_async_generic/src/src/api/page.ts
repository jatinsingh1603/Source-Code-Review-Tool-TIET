import { load } from "./load";

export async function open(id: string) {
  const record = await load<string>(id);
  return record;
}
