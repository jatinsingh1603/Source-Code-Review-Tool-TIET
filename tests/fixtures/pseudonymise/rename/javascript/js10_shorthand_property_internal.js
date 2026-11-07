// extra: req
const { accountId, createdAt } = req.body;      // req is public, both bindings internal
const fee = computeFee({ accountId, tier: "premium" });
