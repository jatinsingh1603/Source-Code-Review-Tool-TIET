function pick(record: Record<string, number> | null): number {
  const value = record!.total as number;
  return value;
}
