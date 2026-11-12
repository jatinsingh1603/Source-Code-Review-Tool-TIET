int fill()
{
  char buf[4];
  for (int i = 0; i < 8; i++)
  {
    buf[i] = 0;
  }
  return buf[0];
}

int use()
{
  int n;
  return n + 1;
}
