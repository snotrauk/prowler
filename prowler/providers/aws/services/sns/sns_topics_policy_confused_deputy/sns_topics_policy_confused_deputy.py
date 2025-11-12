from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.sns.sns_client import sns_client


class sns_topics_policy_confused_deputy(Check):
    def execute(self):
        findings = []
        for topic in sns_client.topics:
            report = Check_Report_AWS(metadata=self.metadata(), resource=topic)
            report.status = "PASS"
            report.status_extended = (
                f"SNS topic {topic.name} is not vulnerable to cross-service confused deputy attacks."
            )

            if topic.policy:
                if is_policy_public(
                    topic.policy,
                    iam_client.audited_account,
                    check_cross_service_confused_deputy=True
                ):
                    report.status = "FAIL"
                    report.status_extended = f"SNS topic {topic.name} is vulnerable to cross-service confused deputy attacks."

            findings.append(report)
        return findings
