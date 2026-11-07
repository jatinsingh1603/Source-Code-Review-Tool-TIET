function merge(firstList, ...otherLists) {
  return [...firstList, ...otherLists.flat()];
}

const combined = { ...baseConfig, extraFlag: true };
