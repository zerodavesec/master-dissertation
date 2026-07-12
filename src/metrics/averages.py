from pandas import DataFrame


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

    def __init__(self, df: DataFrame): ...

    # ---------------------------Generation Method-----------------------------
    @property
    def general_micro_average_gen_method(self) -> dict: ...

    @property
    def general_macro_average_gen_method(self) -> dict: ...

    @property
    def targeted_testing_macro_average_gen_method(self) -> dict: ...

    @property
    def non_targeted_testing_macro_average_gen_method(self) -> dict: ...

    @property
    def targeted_testing_micro_average_gen_method(self) -> dict: ...

    @property
    def non_targeted_testing_micro_average_gen_method(self) -> dict: ...

    # ----------------------------------------------------------------

    # ----------------------------Rule Type------------------------------------
    @property
    def general_micro_average_rule_type(self) -> dict: ...

    @property
    def general_macro_average_rule_type(self) -> dict: ...

    @property
    def targeted_testing_micro_average_rule_type(self) -> dict: ...

    @property
    def targeted_testing_macro_average_rule_type(self) -> dict: ...

    @property
    def non_targeted_testing_macro_average_rule_type(self) -> dict: ...

    @property
    def non_targeted_testing_micro_average_rule_type(self) -> dict: ...

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

    def __calculate_micro_averages(self) -> dict: ...
