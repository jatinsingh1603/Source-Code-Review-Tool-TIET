function outer(value) {
  function inner(value) {
    value = value + 1;
    return value;
  }
  return inner(value);
}
