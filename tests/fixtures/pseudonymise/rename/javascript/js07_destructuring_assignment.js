let accountId;
let createdAt;
({ accountId, createdAt } = loadRecord());
[accountId, createdAt] = [createdAt, accountId];
