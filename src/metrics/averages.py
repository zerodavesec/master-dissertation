from decimal import Decimal
from enum import StrEnum
from typing import Literal, TypedDict

from numpy import test, testing
from pandas import DataFrame

from src.metrics.metrics import Metrics


class MetricsDict(TypedDict):
    """
    This is the base for all returning values for graphs/plots. The final
    nested dict will always follow this pattern
    """

    recall: Decimal
    precision: Decimal
    f1_score: Decimal
    false_positive_rate: Decimal


class GenMethodMetricsDict(TypedDict):
    """
    For Generation Method related Averages, the format will be:
    ```json
    "manual": {
        "recall": Decimal(...),
        "precision": Decimal(...),
        "f1_score": Decimal(...),
        "false_positive_rate": Decimal(...),
    },
    manual_ai: {
       ...
    }
    ```
    """

    manual: MetricsDict
    manual_ai: MetricsDict
    automated: MetricsDict
    automated_ai: MetricsDict


class RuleTypeMetricsDict(TypedDict):
    """
    For Rule Type related Averages, the format will be:
    ```json
    "detection": {
        "recall": Decimal(...),
        "precision": Decimal(...),
        "f1_score": Decimal(...),
        "false_positive_rate": Decimal(...),
    },
    correlation: {
       ...
    }
    ```
    """

    detection: MetricsDict
    correlation: MetricsDict


class AverageFlag(StrEnum):
    MACRO = "macro"
    MICRO = "micro"


class CategoryFlag(StrEnum):
    GEN_METHOD = "generation_method"
    RULE_TYPE = "rule_type"
    MALWARE_FAMILY = "malware_family"
    MALWARE = "malware_type"


class TestingFlag(StrEnum):
    NON_TARGETED_TESTING = "NTT"
    TARGETED_TESTING = "TT"
    ALL = "ALL"


class Averages:
    """
    For the Averages class, this performs a calculation of all averages that
    may be relevant in terms of precision, recall, f1 score, and miss rate.

    Calculations
    -------------
    Targeted vs Non-Targeted Testing: Targeted Testing represents the testing of
    detection rules against the baseline (for false positive/noise) and the
    sample used for rule creation. This tests for any obvious errors in rule creation.
    Non-Targeted Testing represents the testing of the detection rule against the
    rest of the samples to find false negatives. `General` represents an aggregation
    of testing results without regard to the testing type used.

    Type of Classification:
    ----------------------
    Classification for graphs can be based on:
    - Rule Generation Method (manual, manual_ai, automated, automated_ai)
    - Rule Type (detection, correlation)
    - Malware Type (ransomware, trojan, RAT, etc)
    - Malware Family (medusalocker, remcos, etc.)
    """

    def __init__(self, df: DataFrame):
        self.df = df

    # ---------------------------Generation Method-----------------------------
    @property
    def general_micro_average_gen_method(self) -> GenMethodMetricsDict: ...

    @property
    def general_macro_average_gen_method(self) -> GenMethodMetricsDict: ...

    @property
    def targeted_testing_macro_average_gen_method(self) -> GenMethodMetricsDict: ...

    @property
    def non_targeted_testing_macro_average_gen_method(self) -> GenMethodMetricsDict: ...

    @property
    def targeted_testing_micro_average_gen_method(self) -> GenMethodMetricsDict: ...

    @property
    def non_targeted_testing_micro_average_gen_method(self) -> GenMethodMetricsDict: ...

    # ----------------------------------------------------------------

    # ----------------------------Rule Type------------------------------------
    @property
    def general_micro_average_rule_type(self) -> RuleTypeMetricsDict: ...

    @property
    def general_macro_average_rule_type(self) -> RuleTypeMetricsDict: ...

    @property
    def targeted_testing_micro_average_rule_type(self) -> RuleTypeMetricsDict: ...

    @property
    def targeted_testing_macro_average_rule_type(self) -> RuleTypeMetricsDict: ...

    @property
    def non_targeted_testing_macro_average_rule_type(self) -> RuleTypeMetricsDict: ...

    @property
    def non_targeted_testing_micro_average_rule_type(self) -> RuleTypeMetricsDict: ...

    # ----------------------------------------------------------------
    # -----------------------------Malware Type---------------------------------

    @property
    def general_micro_average_mal_type(self) -> dict: ...

    @property
    def general_macro_average_mal_type(self) -> dict: ...

    @property
    def targeted_testing_micro_average_mal_type(self) -> dict: ...

    @property
    def targeted_testing_macro_average_mal_type(self) -> dict: ...

    @property
    def non_targeted_testing_macro_average_mal_type(self) -> dict: ...

    @property
    def non_targeted_testing_micro_average_mal_type(self) -> dict: ...

    # ----------------------------------------------------------------
    # -----------------------------Malware family---------------------------------

    @property
    def general_micro_average_mal_family(self) -> dict: ...

    @property
    def general_macro_average_mal_family(self) -> dict: ...

    @property
    def targeted_testing_micro_average_mal_family(self) -> dict: ...

    @property
    def targeted_testing_macro_average_mal_family(self) -> dict: ...

    @property
    def non_targeted_testing_macro_average_mal_family(self) -> dict: ...

    @property
    def non_targeted_testing_micro_average_mal_family(self) -> dict: ...

    def __calculate_averages(
        self,
        average_flag: AverageFlag,
        category_flag: CategoryFlag,
        testing_flag: TestingFlag,
    ):
        match average_flag:
            case AverageFlag.MACRO:
                self.__calculate_macro_averages(
                    category_flag=category_flag, testing_flag=testing_flag
                )
            case AverageFlag.MICRO:
                self.__calculate_micro_averages(
                    category_flag=category_flag, testing_flag=testing_flag
                )
            case _:
                raise ValueError

    def __calculate_macro_averages(
        self, category_flag: CategoryFlag, testing_flag: TestingFlag
    ): ...

    def __calculate_micro_averages(
        self, category_flag: CategoryFlag, testing_flag: TestingFlag
    ): ...
