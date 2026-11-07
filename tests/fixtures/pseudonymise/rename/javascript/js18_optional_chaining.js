function owner(customer) {
  return customer?.profile?.owner ?? customer?.fallbackOwner;
}
