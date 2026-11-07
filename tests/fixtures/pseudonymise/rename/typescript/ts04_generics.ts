function firstOf<Item>(items: Item[]): Item {
  return items[0];
}

class Box<Content> {
  constructor(public content: Content) {}
}
