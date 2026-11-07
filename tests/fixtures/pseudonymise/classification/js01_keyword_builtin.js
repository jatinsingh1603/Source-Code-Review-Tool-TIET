function render(value) {
  if (value === undefined) {
    return JSON.stringify(Object.keys(value));
  }
  return parseInt(value, 10);
}
