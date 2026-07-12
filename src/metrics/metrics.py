from decimal import Decimal
from typing import Annotated

from annotated_types import Ge


class Metrics:
    def __init__(
        self,
        tp: Annotated[int, Ge(0)],
        fp: Annotated[int, Ge(0)],
        fn: Annotated[int, Ge(0)],
    ) -> None:

        if not (isinstance(tp, int) and isinstance(fp, int) and isinstance(fn, int)):
            raise TypeError

        if min(tp, fp, fn) < 0:
            raise ValueError

        self.tp = Decimal(tp)
        self.fp = Decimal(fp)
        self.fn = Decimal(fn)

    @property
    def precision(self) -> Decimal:
        """
        Precision or Positive Pedicitve Value (PPV), measures the number
        of true positives, divided by the total alerts (true and false positives)
        """
        if self.tp == 0:
            return Decimal(0)
        return self.tp / (self.tp + self.fp)

    @property
    def recall(self) -> Decimal:
        """
        The recall (or True Positive Rate, or Sensitivity) measures the number of
        true positives, divided by real positives (true positives + false negatives)
        """
        if self.tp == 0:
            return Decimal(0)
        return self.tp / (self.tp + self.fn)

    @property
    def f1_score(self) -> Decimal:
        """
        The F1 score is the harmonic mean of precision and recall.

        if true positive number == 0 -> F1 Score = 0
        """
        if self.tp == 0:
            return Decimal(0)
        return Decimal(2) * (
            (self.precision * self.recall) / (self.precision + self.recall)
        )

    @property
    def false_negative_rate(self) -> Decimal:
        """
        FNR or also known as "miss rate". Number of FNs divided by real positives.

        if false negatives == 0 -> FNR = 0
        """
        if self.fn == 0:
            return Decimal(0)
        return self.fn / (self.tp + self.fn)


def main() -> None: ...


if __name__ == "__main__":
    main()
