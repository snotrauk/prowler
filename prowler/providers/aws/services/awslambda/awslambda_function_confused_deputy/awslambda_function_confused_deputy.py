from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.awslambda.awslambda_service import AuthType

import re

class awslambda_function_confused_deputy(Check):
    def execute(self):
        findings = []

        global_conditions = [ "aws:SourceArn", "aws:SourceAccount", "aws:SourceOrgID", "aws:SourceOrgPaths", "AWS:SourceArn", "AWS:SourceAccount", "AWS:SourceOrgID", "AWS:SourceOrgPaths", "aws:PrincipalArn", "aws:PrincipalAccount", "aws:PrincipalOrgID", "aws:PrincipalOrgPaths", "AWS:PrincipalArn", "AWS:PrincipalAccount", "AWS:PrincipalOrgID", "AWS:PrincipalOrgPaths" ]

        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)
            report.status_extended = f"Lambda function {function.name} has a resource policy that prevents cross-service confused deputy attacks."
            report.status = "PASS"
            for statement in function.policy.get("Statement", ""):
                if statement.get("Effect", "") == "Allow":
                    try:
                        if re.match(r"^.*\.amazonaws\.com", str(statement["Principal"]["Service"])):
                            if "Condition" not in statement:
                                report.status_extended = f"Lambda function {function.name} has a resource policy that does not prevent cross-service confused deputy attacks."
                                report.status = "FAIL"
                            else:
                                if not any(item in statement["Condition"]["StringEquals"] for item in global_conditions):
                                    report.status_extended = f"Lambda function {function.name} has a resource policy that does not prevent cross-service confused deputy attacks."
                                    report.status = "FAIL"
                    except KeyError:
                        pass


            findings.append(report)


        return findings
