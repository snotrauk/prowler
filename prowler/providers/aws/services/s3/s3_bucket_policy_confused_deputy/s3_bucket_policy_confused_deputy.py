from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.s3.s3_client import s3_client
from prowler.providers.aws.services.s3.s3control_client import s3control_client

class s3_bucket_policy_confused_deputy(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            report.status = "PASS"
            report.status_extended = f"S3 Bucket {bucket.name} is not vulnerable to confused deputy attacks"
            if bucket.policy is None:
                pass
            else:
                if is_policy_public(
                    bucket.policy,
                    s3_client.audited_account,
                    check_cross_service_confused_deputy=True
                ):
                    report.status == "FAIL"
                    report.status_extended = f"S3 Bucket {bucket.name} is vulnerable to confused deputy attacks"

            findings.append(report)

        return findings
