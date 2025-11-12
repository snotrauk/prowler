from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_key_policy_confused_deputy(Check):
    def execute(self):
        findings = []
        for key in kms_client.keys:
            report = Check_Report_AWS(metadata=self.metadata(), resource=key)
            report.status = "PASS"
            report.status_extended = f"KMS key {key.id} is not vulnerable to confused deputy attacks."
            if key.policy == None:
                pass
            else:
                if is_policy_public(
                    key.policy,
                    kms_client.audited_account,
                    check_cross_service_confused_deputy=True,
                    not_allowed_actions=["kms:*"],
                ):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"KMS key {key.id} is vulnerable to confused deputy attacks."
                    )
            findings.append(report)
        return findings
