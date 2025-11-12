from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_group_unused(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        for group in iam_client.groups:
            report = Check_Report_AWS(metadata=self.metadata(), resource=group)
            report.region = iam_client.region
            report.status = "PASS"
            report.status_extended = (
                f"IAM Group {group.name} is in use."
            )
            if group.users == []:
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM Group {group.name} has no users and is therefore unused."
                )

            findings.append(report)

        return findings
