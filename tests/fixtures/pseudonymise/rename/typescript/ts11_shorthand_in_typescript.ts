// extra: res
function handler(accountId: string, res: Response) {
  const total = computeTotal(accountId);
  return res.json({ accountId, total });
}
