function charge(items) {
  const fee = 2;
  function total(list) {
    return eval(list.join('+')) + fee;
  }
  return total(items);
}
