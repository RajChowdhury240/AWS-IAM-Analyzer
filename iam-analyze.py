import boto3
import csv
import datetime
import json
import requests
from rich import print
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()
iam = boto3.client('iam')
securityhub = boto3.client('securityhub')

SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

def list_iam_users():
    users = iam.list_users()['Users']
    mfa_devices = {mfa['UserName'] for mfa in iam.list_mfa_devices()['MFADevices']}

    table = Table(title="[bold blue]IAM Users Detailed Report[/bold blue]", header_style="bold magenta")
    table.add_column("Username", style="cyan", no_wrap=True)
    table.add_column("Created Date", style="green")
    table.add_column("MFA Enabled", style="yellow")
    table.add_column("Console Access", style="red")
    table.add_column("Inactive (90+ Days)", style="bold white")
    table.add_column("Old Access Keys (90+ Days)", style="blue")

    report_data = []

    for user in track(users, description="[green]Analyzing IAM Users...[/green]"):
        username = user['UserName']
        created_date = user['CreateDate'].strftime('%Y-%m-%d')
        mfa_enabled = 'Yes' if username in mfa_devices else 'No'
        console_access = 'Yes' if 'PasswordLastUsed' in user else 'No'
        last_used = user.get('PasswordLastUsed', None)
        inactive_days = (datetime.datetime.now(datetime.timezone.utc) - last_used).days if last_used else None
        inactive_90_days = 'Yes' if (inactive_days is None or inactive_days > 90) else 'No'
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        old_keys = [key['AccessKeyId'] for key in keys if (datetime.datetime.now(datetime.timezone.utc) - key['CreateDate']).days > 90]
        old_keys_status = 'Yes' if old_keys else 'No'

        table.add_row(username, created_date, mfa_enabled, console_access, inactive_90_days, old_keys_status)

        report_data.append({
            'Username': username,
            'Created Date': created_date,
            'MFA Enabled': mfa_enabled,
            'Console Access': console_access,
            'Inactive (90+ Days)': inactive_90_days,
            'Old Access Keys (90+ Days)': old_keys_status
        })

    console.print(table)
    generate_csv('iam_users_report.csv', report_data)
    send_slack_alert(report_data)

def list_iam_roles():
    roles = iam.list_roles()['Roles']
    table = Table(title="[bold blue]IAM Roles Detailed Report[/bold blue]", header_style="bold magenta")
    table.add_column("Role Name", style="cyan", no_wrap=True)
    table.add_column("Trusted Entities", style="green")
    table.add_column("Administrator Access", style="red")

    report_data = []

    for role in track(roles, description="[green]Analyzing IAM Roles...[/green]"):
        role_name = role['RoleName']
        assume_role_policy = role.get('AssumeRolePolicyDocument', {}).get('Statement', [])
        
        trusted_entities_list = []
        for stmt in assume_role_policy:
            principal = stmt.get('Principal', {})
            if 'AWS' in principal:
                aws_principals = principal['AWS']
                trusted_entities_list.extend(aws_principals if isinstance(aws_principals, list) else [aws_principals])
            if 'Service' in principal:
                service_principals = principal['Service']
                trusted_entities_list.extend(service_principals if isinstance(service_principals, list) else [service_principals])
            if 'Federated' in principal:
                federated_principals = principal['Federated']
                trusted_entities_list.extend(federated_principals if isinstance(federated_principals, list) else [federated_principals])

        trusted_entities = ', '.join(trusted_entities_list) if trusted_entities_list else 'None'

        admin_access = 'No'
        attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        for policy in attached_policies:
            if 'AdministratorAccess' in policy['PolicyName']:
                admin_access = 'Yes'
                break

        table.add_row(role_name, trusted_entities, admin_access)

        report_data.append({
            'Role Name': role_name,
            'Trusted Entities': trusted_entities,
            'Administrator Access': admin_access
        })

    console.print(table)
    generate_csv('iam_roles_report.csv', report_data)

def generate_csv(filename, data):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = data[0].keys() if data else []
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    console.print(f"\n[bold green]CSV report '{filename}' generated successfully![/bold green]")

def send_slack_alert(report_data):
    message = "IAM Security Findings:\n" + json.dumps(report_data, indent=2)
    requests.post(SLACK_WEBHOOK_URL, json={"text": message})
    console.print("[bold cyan]Slack alert sent![/bold cyan]")

def main():
    console.rule("[bold red]AWS IAM Analyzer & Hardener[/bold red]")
    list_iam_users()
    list_iam_roles()
    console.print("[bold blue]\nIAM analysis completed successfully![/bold blue]")

if __name__ == "__main__":
    main()
