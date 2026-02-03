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

    WIKI = (
        "https://github.com/crytic/slither/wiki/Detector-Documentation#generic-slippage"
    )

    WIKI_TITLE = "Sandwich Vulnerabilities"

    # region wiki_description
    WIKI_DESCRIPTION = """
Detects sandwich vulnerabilities."""
    # endregion wiki_description

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
if (returnAmount < desc.minReturnAmount) revert RouterErrors.ReturnAmountIsNotEnough();
```
"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = """Use oracles and do not set slippage by yourself."""

    STANDARD_JSON = False

    def _detect(self):
        results = []

        for contract in self.slither.contracts:
            for function in contract.functions:
                # 1. Identify all user-controlled parameters
                user_params = function.parameters

                # 2. Identify all variables written to by external calls (The "Swap Result")
                call_results = set()
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, (HighLevelCall, LowLevelCall)):
                            # Capture the variable storing the return value (LHS)
                            if ir.lvalue:
                                call_results.add(ir.lvalue)

                if not call_results:
                    continue

                # 3. Analyze conditions for the "Triangle" pattern
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, Condition):
                            # Get all variables involved in this condition (e.g., "a" and "b" in "a > b")
                            condition_vars = node.variables_read
                            
                            # === FIX START ===
                            
                            # Check 1: Does any variable in the condition depend on a USER PARAMETER?
                            tainted_by_param = []
                            for var in condition_vars:
                                for param in user_params:
                                    # Check if 'var' (in the if) is dependent on 'param' (user input)
                                    if is_dependent(var, param, contract):
                                        tainted_by_param.append(param)
                                        
                            # Check 2: Does any variable in the condition depend on an EXTERNAL CALL RESULT?
                            tainted_by_call = []
                            for var in condition_vars:
                                for res in call_results:
                                    # Check if 'var' (in the if) is dependent on 'res' (swap output)
                                    if is_dependent(var, res, contract):
                                        tainted_by_call.append(res)
                            
                            # === FIX END ===

                            # If BOTH are true, the condition links a user param to a call result
                            if tainted_by_param and tainted_by_call:
                                # Remove duplicates for cleaner output
                                param_names = list(set([p.name for p in tainted_by_param]))
                                call_names = list(set([r.name for r in tainted_by_call if r.name]))

                                info = [
                                    function,
                                    f" generic slippage pattern detected at line {node.source_mapping.lines}.\n"
                                    f"\t- Condition depends on user param: {param_names}\n"
                                    f"\t- Condition depends on external call result: {call_names}"
                                ]
                                results.append(self.generate_result(info))

        return results