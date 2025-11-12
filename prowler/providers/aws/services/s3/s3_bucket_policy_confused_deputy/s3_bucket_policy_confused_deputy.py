from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.s3.s3_client import s3_client
from prowler.providers.aws.services.s3.s3control_client import s3control_client

import re


class s3_bucket_policy_confused_deputy(Check):
    def execute(self):
        findings = []
        global_conditions = [ "aws:SourceArn", "aws:SourceAccount", "aws:SourceOrgID", "aws:SourceOrgPaths", "AWS:SourceArn", "AWS:SourceAccount", "AWS:SourceOrgID", "AWS:SourceOrgPaths", "aws:PrincipalArn", "aws:PrincipalAccount", "aws:PrincipalOrgID", "aws:PrincipalOrgPaths", "AWS:PrincipalArn", "AWS:PrincipalAccount", "AWS:PrincipalOrgID", "AWS:PrincipalOrgPaths" ]

        for bucket in s3_client.buckets.values():
            if bucket.policy is None:
                pass
            else:
                report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
                report.status = "PASS"
                report.status_extended = f"S3 Bucket {bucket.name} is not vulnerable to confused deputy attacks"
                for statement in bucket.policy.get("Statement", ""):
                    if statement["Effect"] == "Allow":
                        try:

                            if statement["Principal"] == "*":
                                if "Condition" not in statement:
                                    report.status = "FAIL"
                                else:
                                    if not any(item in statement["Condition"]["StringEquals"] for item in global_conditions):
                                        report.status = "FAIL"

                            if re.match(r"^.*\.amazonaws\.com", str(statement["Principal"]["Service"])):
                                if "Condition" not in statement:
                                    report.status = "FAIL"
                                else:
                                    if not any(item in statement["Condition"]["StringEquals"] for item in global_conditions):
                                        report.status = "FAIL"
                        except KeyError:
                            pass
                        except TypeError:
                            pass

            if report.status == "FAIL":
                report.status_extended = f"S3 Bucket {bucket.name} is vulnerable to confused deputy attacks"

            if report:
                findings.append(report)

        return findings
