from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import cloudtrail_client

class cloudtrail_duplicate_global_logging(Check):
    def execute(self):
        findings = []
        global_logging_trails = []
        report = Check_Report_AWS(metadata=self.metadata(), resource={})
        report.resource_id = cloudtrail_client.audited_account
        report.resource_arn = cloudtrail_client.audited_account_arn
        report.region = cloudtrail_client.region
        if cloudtrail_client.trails is not None:
            for trail in cloudtrail_client.trails.values():
                if trail.include_global_service_events:
                    global_logging_trails.append(trail)

        if len(global_logging_trails) > 1:
            report.status = "FAIL"
            report.status_extended = "Multiple Trails have global service logging enabled"
        else:
            report.status = "PASS"
            report.status_extended = "Multiple Trails do not have global service logging enabled"

        findings.append(report)
        return findings
