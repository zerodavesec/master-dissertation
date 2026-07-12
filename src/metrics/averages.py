import json
from decimal import Decimal
from enum import StrEnum
from typing import Literal, TypedDict
from unittest import TestSuite

import pandas as pd
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
    false_negative_rate: Decimal


class GenMethodMetricsDict(TypedDict):
    """
    For Generation Method related Averages, the format will be:
    ```json
    "manual": {
        "recall": Decimal(...),
        "precision": Decimal(...),
        "f1_score": Decimal(...),
        "false_negative_rate": Decimal(...),
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
        "false_negative_rate": Decimal(...),
    },
    correlation: {
       ...
    }
    ```
    """

    detection: MetricsDict
    correlation: MetricsDict


AveragesDict = GenMethodMetricsDict | RuleTypeMetricsDict


class AverageFlag(StrEnum):
    MACRO = "macro"
    MICRO = "micro"


class CategoryFlag(StrEnum):
    GEN_METHOD = "generation_method"
    RULE_TYPE = "rule_type"
    MALWARE_TYPE = "malware_type"
    MALWARE_FAMILY = "malware_family"


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
    def general_macro_average_gen_method(self) -> AveragesDict:
        return self.__calculate_averages(
            average_flag=AverageFlag.MACRO, category_flag=CategoryFlag.GEN_METHOD
        )

    @property
    def targeted_testing_macro_average_gen_method(self) -> AveragesDict:
        return self.__calculate_averages(
            average_flag=AverageFlag.MACRO,
            category_flag=CategoryFlag.GEN_METHOD,
            testing_flag=TestingFlag.TARGETED_TESTING,
        )

    @property
    def non_targeted_testing_macro_average_gen_method(self) -> AveragesDict:
        return self.__calculate_averages(
            average_flag=AverageFlag.MACRO,
            category_flag=CategoryFlag.GEN_METHOD,
            testing_flag=TestingFlag.NON_TARGETED_TESTING,
        )

    @property
    def general_micro_average_gen_method(self) -> GenMethodMetricsDict: ...

    @property
    def targeted_testing_micro_average_gen_method(self) -> GenMethodMetricsDict: ...

    @property
    def non_targeted_testing_micro_average_gen_method(self) -> GenMethodMetricsDict: ...

    # ----------------------------------------------------------------

    # ----------------------------Rule Type------------------------------------
    @property
    def general_micro_average_rule_type(self) -> RuleTypeMetricsDict: ...

    @property
    def general_macro_average_rule_type(self) -> AveragesDict:
        return self.__calculate_averages(
            average_flag=AverageFlag.MACRO, category_flag=CategoryFlag.RULE_TYPE
        )

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
        testing_flag: TestingFlag = TestingFlag.ALL,
    ) -> AveragesDict:
        match average_flag:
            case AverageFlag.MACRO:
                return self.__calculate_macro_averages(
                    category_flag=category_flag, testing_flag=testing_flag
                )
            case AverageFlag.MICRO:
                return self.__calculate_micro_averages(
                    category_flag=category_flag, testing_flag=testing_flag
                )
            case _:
                raise ValueError

    def __calculate_macro_averages(
        self, category_flag: CategoryFlag, testing_flag: TestingFlag
    ) -> AveragesDict:
        match category_flag:
            case CategoryFlag.GEN_METHOD:
                return self.__calculate_macro_averages_gen_method(
                    testing_flag=testing_flag
                )
            case CategoryFlag.RULE_TYPE:
                return self.__calculate_macro_averages_rule_type(
                    testing_flag=testing_flag
                )
            case CategoryFlag.MALWARE_TYPE:
                return self.__calculate_macro_averages_malware_type(
                    testing_flag=testing_flag
                )
            case CategoryFlag.MALWARE_FAMILY:
                return self.__calculate_macro_averages_malware_family(
                    testing_flag=testing_flag
                )
            case _:
                raise ValueError

    def __calculate_macro_averages_gen_method(
        self, testing_flag: TestingFlag
    ) -> GenMethodMetricsDict:
        metrics_dict: GenMethodMetricsDict = {}  # type: ignore
        mapping = {
            "manual": "MAN",
            "manual_ai": "MAI",
            "automated": "AUT",
            "automated_ai": "AI",
        }
        match testing_flag:
            case TestingFlag.ALL:
                for key, value in mapping.items():
                    individual_values: dict[str, dict[str, int]] = (
                        self.df.loc[
                            (self.df["Rule Generation Method"] == value),
                            [
                                "ID",
                                "True Positives (TP)",
                                "False Positives (FP)",
                                "False Negatives (FN)",
                            ],
                        ]
                        .set_index("ID")
                        .to_dict(orient="index")
                    )

                    precision_list: list[Decimal] = []
                    recall_list: list[Decimal] = []
                    f1_score_list: list[Decimal] = []
                    false_negative_rate_list: list[Decimal] = []
                    for item in individual_values:
                        metric: Metrics = Metrics(
                            tp=individual_values[item]["True Positives (TP)"],
                            fp=individual_values[item]["False Positives (FP)"],
                            fn=individual_values[item]["False Negatives (FN)"],
                        )
                        precision_list.append(metric.precision)
                        recall_list.append(metric.recall)
                        f1_score_list.append(metric.f1_score)
                        false_negative_rate_list.append(metric.false_negative_rate)

                        metrics_dict[key] = {
                            "recall": Decimal(sum(recall_list) / len(recall_list)),
                            "precision": Decimal(
                                sum(precision_list) / len(precision_list)
                            ),
                            "f1_score": Decimal(
                                sum(f1_score_list) / len(f1_score_list)
                            ),
                            "false_negative_rate": Decimal(
                                sum(false_negative_rate_list)
                                / len(false_negative_rate_list)
                            ),
                        }
                return metrics_dict

            case TestingFlag.NON_TARGETED_TESTING:
                for key, value in mapping.items():
                    individual_values: dict[str, dict[str, int]] = (
                        self.df.loc[
                            (self.df["Rule Generation Method"] == value)
                            & (
                                self.df["Testing Type"]
                                == TestingFlag.NON_TARGETED_TESTING
                            ),
                            [
                                "ID",
                                "True Positives (TP)",
                                "False Positives (FP)",
                                "False Negatives (FN)",
                            ],
                        ]
                        .set_index("ID")
                        .to_dict(orient="index")
                    )

                    precision_list: list[Decimal] = []
                    recall_list: list[Decimal] = []
                    f1_score_list: list[Decimal] = []
                    false_negative_rate_list: list[Decimal] = []
                    for item in individual_values:
                        metric: Metrics = Metrics(
                            tp=individual_values[item]["True Positives (TP)"],
                            fp=individual_values[item]["False Positives (FP)"],
                            fn=individual_values[item]["False Negatives (FN)"],
                        )
                        precision_list.append(metric.precision)
                        recall_list.append(metric.recall)
                        f1_score_list.append(metric.f1_score)
                        false_negative_rate_list.append(metric.false_negative_rate)

                        metrics_dict[key] = {
                            "recall": Decimal(sum(recall_list) / len(recall_list)),
                            "precision": Decimal(
                                sum(precision_list) / len(precision_list)
                            ),
                            "f1_score": Decimal(
                                sum(f1_score_list) / len(f1_score_list)
                            ),
                            "false_negative_rate": Decimal(
                                sum(false_negative_rate_list)
                                / len(false_negative_rate_list)
                            ),
                        }
                return metrics_dict

            case TestingFlag.TARGETED_TESTING:
                for key, value in mapping.items():
                    individual_values: dict[str, dict[str, int]] = (
                        self.df.loc[
                            (self.df["Rule Generation Method"] == value)
                            & (self.df["Testing Type"] == TestingFlag.TARGETED_TESTING),
                            [
                                "ID",
                                "True Positives (TP)",
                                "False Positives (FP)",
                                "False Negatives (FN)",
                            ],
                        ]
                        .set_index("ID")
                        .to_dict(orient="index")
                    )

                    precision_list: list[Decimal] = []
                    recall_list: list[Decimal] = []
                    f1_score_list: list[Decimal] = []
                    false_negative_rate_list: list[Decimal] = []
                    for item in individual_values:
                        metric: Metrics = Metrics(
                            tp=individual_values[item]["True Positives (TP)"],
                            fp=individual_values[item]["False Positives (FP)"],
                            fn=individual_values[item]["False Negatives (FN)"],
                        )
                        precision_list.append(metric.precision)
                        recall_list.append(metric.recall)
                        f1_score_list.append(metric.f1_score)
                        false_negative_rate_list.append(metric.false_negative_rate)

                        metrics_dict[key] = {
                            "recall": Decimal(sum(recall_list) / len(recall_list)),
                            "precision": Decimal(
                                sum(precision_list) / len(precision_list)
                            ),
                            "f1_score": Decimal(
                                sum(f1_score_list) / len(f1_score_list)
                            ),
                            "false_negative_rate": Decimal(
                                sum(false_negative_rate_list)
                                / len(false_negative_rate_list)
                            ),
                        }
                    return metrics_dict

        raise ValueError

    def __calculate_macro_averages_rule_type(
        self, testing_flag: TestingFlag
    ) -> RuleTypeMetricsDict:
        metrics_dict: RuleTypeMetricsDict = {}  # type: ignore

        mapping = {"detection": "DET", "correlation": "CORR"}

        match testing_flag:
            case TestingFlag.ALL:
                for key, value in mapping.items():
                    individual_values: dict[str, dict[str, int]] = (
                        self.df.loc[
                            (self.df["Rule Type"] == value),
                            [
                                "ID",
                                "True Positives (TP)",
                                "False Positives (FP)",
                                "False Negatives (FN)",
                            ],
                        ]
                        .set_index("ID")
                        .to_dict(orient="index")
                    )

                    precision_list: list[Decimal] = []
                    recall_list: list[Decimal] = []
                    f1_score_list: list[Decimal] = []
                    false_negative_rate_list: list[Decimal] = []
                    for item in individual_values:
                        metric: Metrics = Metrics(
                            tp=individual_values[item]["True Positives (TP)"],
                            fp=individual_values[item]["False Positives (FP)"],
                            fn=individual_values[item]["False Negatives (FN)"],
                        )
                        precision_list.append(metric.precision)
                        recall_list.append(metric.recall)
                        f1_score_list.append(metric.f1_score)
                        false_negative_rate_list.append(metric.false_negative_rate)

                        metrics_dict[key] = {
                            "recall": Decimal(sum(recall_list) / len(recall_list)),
                            "precision": Decimal(
                                sum(precision_list) / len(precision_list)
                            ),
                            "f1_score": Decimal(
                                sum(f1_score_list) / len(f1_score_list)
                            ),
                            "false_negative_rate": Decimal(
                                sum(false_negative_rate_list)
                                / len(false_negative_rate_list)
                            ),
                        }
                return metrics_dict
            case TestingFlag.NON_TARGETED_TESTING:
                ...
            case TestingFlag.TARGETED_TESTING:
                ...

        raise ValueError

    def __calculate_macro_averages_malware_type(self, testing_flag: TestingFlag): ...

    def __calculate_macro_averages_malware_family(self, testing_flag: TestingFlag): ...

    def __calculate_micro_averages(
        self, category_flag: CategoryFlag, testing_flag: TestingFlag
    ) -> AveragesDict:
        match category_flag:
            case CategoryFlag.GEN_METHOD:
                ...
            case CategoryFlag.RULE_TYPE:
                ...
            case CategoryFlag.MALWARE_TYPE:
                ...
            case CategoryFlag.MALWARE_FAMILY:
                ...

        raise ValueError


if __name__ == "__main__":
    df = pd.read_csv("/Users/zerodave/Documents/Dissertation.csv")
    averages = Averages(df)
    print(json.dumps(averages.general_macro_average_gen_method, default=float))
    print(
        json.dumps(
            averages.non_targeted_testing_macro_average_gen_method, default=float
        )
    )
    print(json.dumps(averages.targeted_testing_macro_average_gen_method, default=float))
    print(json.dumps(averages.general_macro_average_rule_type, default=float))
