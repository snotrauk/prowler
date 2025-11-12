from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.kms.kms_client import kms_client

import re

class kms_key_policy_overly_permissive(Check):
    def execute(self):
        findings = []
        for key in kms_client.keys:
            if (
                key.manager == "CUSTOMER"
                and key.state == "Enabled"
                and key.policy is not None
            ):  # only customer KMS have policies
                report = Check_Report_AWS(metadata=self.metadata(), resource=key)
                report.status = "PASS"
                report.status_extended = f"KMS key {key.id} does not have an overly permissive policy."

                for statement in key.policy.get("Statement", ""):
                    if statement["Effect"] == "Allow":
                        if "AWS" in statement["Principal"]:
                            if re.match(r"arn:aws:iam::[0-9]+:root", str(statement["Principal"]["AWS"])):
                                report.status = "FAIL"
                                report.status_extended = f"KMS key {key.id} has a policy that is overly permissive"
                            if statement["Principal"] == { "AWS": "*" } or statement["Principal"] == "*":
                                if "Condition" in statement:
                                    if "aws:SourceAccount" in statement["Condition"]["StringEquals"]:
                                        if "aws:SourceArn" not in statement["Condition"]["StringEquals"]:
                                            report.status = "FAIL"
                                            report.status_extended = f"KMS key {key.id} has a policy that is overly permissive"

                findings.append(report)

        return findings
