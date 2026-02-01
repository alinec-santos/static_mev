from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import HighLevelCall, LowLevelCall, Condition
from slither.analyses.data_dependency.data_dependency import is_dependent

class GenericSlippageDetector(AbstractDetector):
    """
    Generic detector for user-controlled constraints on external calls.
    Matches pattern: require(ExternalCallResult >= UserInput)
    """
    
    ARGUMENT = 'generic-slippage'
    HELP = 'Detects user-controlled constraints on external call results'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []

        for contract in self.slither.contracts:
            for function in contract.functions:
                # 1. Identify all user-controlled parameters
                user_params = function.parameters

                # 2. Identify all variables written to by external calls (The "Swap Result")
                call_results = set()
                for node in function.nodes:
                    for ir in node.ir:
                        if isinstance(ir, (HighLevelCall, LowLevelCall)):
                            # Capture the variable storing the return value (LHS)
                            if ir.lvalue:
                                call_results.add(ir.lvalue)

                if not call_results:
                    continue

                # 3. Analyze conditions for the "Triangle" pattern
                for node in function.nodes:
                    for ir in node.ir:
                        if isinstance(ir, Condition):
                            # Get all variables involved in this condition (e.g., "a" and "b" in "a > b")
                            condition_vars = node.variables_read

                            # Check 1: Does the condition depend on a USER PARAMETER?
                            tainted_by_param = [
                                param for param in user_params 
                                if is_dependent(param, condition_vars, contract)
                            ]

                            # Check 2: Does the condition depend on an EXTERNAL CALL RESULT?
                            tainted_by_call = [
                                res for res in call_results 
                                if is_dependent(res, condition_vars, contract)
                            ]

                            # If BOTH are true, we found a generic slippage check
                            if tainted_by_param and tainted_by_call:
                                info = [
                                    function,
                                    f" generic slippage pattern detected at line {node.source_mapping.lines}.\n"
                                    f"\t- Constrained by user param: {[p.name for p in tainted_by_param]}\n"
                                    f"\t- Depends on external call result: {[r.name for r in tainted_by_call]}"
                                ]
                                results.append(self.generate_result(info))

        return results