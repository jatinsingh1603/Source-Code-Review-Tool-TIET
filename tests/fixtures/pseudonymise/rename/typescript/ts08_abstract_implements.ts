interface Policy {
  rate(): number;
}

abstract class BasePolicy implements Policy {
  abstract rate(): number;
}

class SeniorPolicy extends BasePolicy {
  rate(): number {
    return 2;
  }
}
