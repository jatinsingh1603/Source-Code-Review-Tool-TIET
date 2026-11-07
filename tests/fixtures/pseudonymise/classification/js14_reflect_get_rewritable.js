function festivalBonusRate() {
  return 1.1;
}

function readRate(target) {
  return Reflect.get(target, 'festivalBonusRate');
}
