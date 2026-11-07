async function* streamRows(sessionHandle) {
  for await (const chunkRow of sessionHandle.rows()) {
    yield chunkRow;
  }
}
