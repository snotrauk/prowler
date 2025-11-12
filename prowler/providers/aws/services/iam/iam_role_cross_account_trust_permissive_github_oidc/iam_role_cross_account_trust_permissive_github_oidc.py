from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public

import re


class iam_role_cross_account_trust_permissive_github_oidc(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if iam_client.roles:
            for role in iam_client.roles:
                if "aws-service-role" not in role.arn:
                    safe = True
                    report = Check_Report_AWS(metadata=self.metadata(), resource=role)
                    report.region = iam_client.region
                    report.status = "PASS"
                    report.resource_id = role.name
                    report.resource_arn = role.arn
                    report.status_extended = f"The IAM Role {role.name} does not have an overly permissive GitHub OIDC trust policy."
                    statements = role.assume_role_policy.get("Statement")
                    for statement in statements:
                        if statement["Effect"] == "Allow":
                            if "Federated" in statement["Principal"]:
                                if re.match(r"^.*oidc-provider/token.actions.githubusercontent.com", statement["Principal"]["Federated"]):
                                    if "sts:AssumeRoleWithWebIdentity" in statement["Action"]:
                                        safe = False
                                        for condition, values in statement["Condition"].items():
                                            if "token.actions.githubusercontent.com:sub" in values:
                                                safe = True

                    if safe == False:
                        report.region = iam_client.region
                        report.status = "FAIL"
                        report.resource_id = role.name
                        report.resource_arn = role.arn
                        report.status_extended = f"The IAM Role {role.name} has an overly permissive GitHub OIDC trust policy."

                    findings.append(report)


        return findings
