from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

import re


class iam_group_name_indicate_admin(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        for group in iam_client.groups:
            report = Check_Report_AWS(metadata=self.metadata(), resource=group)
            report.region = iam_client.region
            report.status = "PASS"
            report.status_extended = (
                f"IAM Group {group.name} either doesnt have admin access or name correctly indicates that it does"
            )
            for policy in group.attached_policies:
                if policy["PolicyName"] == "AdministratorAccess":
                    if not re.match(r".*[Aa][Dd][Mm][Ii][Nn].*", group.name):
                        report.region = iam_client.region
                        report.status = "FAIL"
                        report.status_extended = (
                            f"IAM Group {group.name} grants administrator access but does not indicate this in the name."
                        )
                        break

            for arn in iam_client.policies:
                if iam_client.policies[arn].name in group.inline_policies:
                    for statement in iam_client.policies[arn].document["Statement"]:
                        if statement["Effect"] == "Allow":
                            if statement["Action"] == "*":
                                if statement["Resource"] == "*":
                                    if not re.match(r".*[Aa][Dd][Mm][Ii][Nn].*", group["Group"]["GroupName"]):
                                        report.status = "FAIL"
                                        report.status_extended = (
                                            f"IAM Group {group.name} grants administrator access but does not indicate this in the name."
                                        )
                                        break

            findings.append(report)

        return findings
