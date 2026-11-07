class BasePolicy:
    def rate(self):
        return 1


class SeniorPolicy(BasePolicy):
    def rate(self):
        return super().rate() + 1
