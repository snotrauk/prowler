from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.kms.kms_client import kms_client

import re


class kms_key_default(Check):
    def execute(self):
        findings = []
        for key in kms_client.keys:
            if key.state == "Enabled":
                report = Check_Report_AWS(metadata=self.metadata(), resource=key)
                report.status = "PASS"
                report.status_extended = f"KMS key {key.id} is not default."
                if re.match("^Default ", key.description):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"KMS key {key.id} is a default key."
                    )
            findings.append(report)
        return findings
