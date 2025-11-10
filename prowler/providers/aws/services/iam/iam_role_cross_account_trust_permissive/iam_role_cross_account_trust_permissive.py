from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public

import re


class iam_role_cross_account_trust_permissive(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if iam_client.roles:
            for role in iam_client.roles:
                account_id = re.match(r"arn:aws:iam::([0-9]+):", role.arn).group(1) # is there a better way? audited_account?
                report = Check_Report_AWS(metadata=self.metadata(), resource=role)
                report.region = iam_client.region
                report.status = "PASS"
                report.resource_id = role.name
                report.resource_arn = role.arn
                report.status_extended = f"Cross-Account IAM Role {role.name} does not have an overly permissive trust policy."
                if "aws-service-role" not in role.arn:
                    statements = role.assume_role_policy.get("Statement")
                    report.resource_details = f"{ statements }"
                    for statement in statements:
                        if statement["Effect"] == "Allow":
                            if "AWS" in statement["Principal"]:
                                if "sts:AssumeRole" in statement["Action"]:
                                    if re.match(r"arn:aws:iam::[0-9]+:root", str(statement["Principal"]["AWS"])): # check if whole account is trusted
                                        if account_id != re.match(r"arn:aws:iam::([0-9]+):root", str(statement["Principal"]["AWS"])).group(1): # ensure trust is of external account
                                            report.region = iam_client.region
                                            report.status = "FAIL"
                                            report.resource_id = role.name
                                            report.resource_arn = role.arn
                                            report.status_extended = f"Cross-Account IAM Role {role.name} has an overly permissive trust policy."

                    findings.append(report)

        return findings
