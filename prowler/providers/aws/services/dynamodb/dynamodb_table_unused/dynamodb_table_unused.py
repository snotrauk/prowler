from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dynamodb.dynamodb_client import dynamodb_client


class dynamodb_table_unused(Check):
    def execute(self):
        findings = []
        for table in dynamodb_client.tables.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=table)
            report.status = "PASS"
            report.status_extended = f"DynamoDB table {table.name} has {table.item_count} items."

            if table.item_count == 0:
                report.status = "FAIL"
                report.status_extended = (
                    f"DynamoDB table {table.name} has no items."
                )

            findings.append(report)

        return findings
