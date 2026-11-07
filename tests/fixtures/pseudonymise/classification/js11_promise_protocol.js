async function fetchAccount(id) {
  return fetch(`/accounts/${id}`).then((r) => r.json()).catch(() => null);
}
