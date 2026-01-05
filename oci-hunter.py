#!/usr/bin/env python3
"""
OCI IAM Enumeration & Privilege Escalation Tool
A professional tool for security testing and IAM assessment in Oracle Cloud Infrastructure

Author: Security Research Team
Version: 2.0.0
License: MIT
"""

import oci
import argparse
import json
import sys
from typing import Dict, List, Optional
from datetime import datetime
import os
import base64

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    banner = f"""
{Colors.OKCYAN}
    ════════════════════════════════════════════════════════════
    
                      {Colors.BOLD}OCI-HUNTER v2.0.0{Colors.OKCYAN}
    
                {Colors.WARNING}Oracle Cloud Security Scanner{Colors.OKCYAN}
    
             {Colors.ENDC}Enumerate • Analyze • Assess • Report{Colors.OKCYAN}
    
                  {Colors.ENDC}IAM  |  Vaults  |  Storage{Colors.OKCYAN}
    
             {Colors.ENDC}For Authorized Security Testing Only{Colors.OKCYAN}
                        {Colors.ENDC}License: MIT{Colors.OKCYAN}
    
    ════════════════════════════════════════════════════════════
{Colors.ENDC}
    """
    print(banner)

class OCISecurityScanner:
    
    def __init__(self, config_file: str = "~/.oci/config", profile: str = "DEFAULT", verbose: bool = False):
        self.verbose = verbose
        self.profile = profile
        self.config_file = os.path.expanduser(config_file)
        
        try:
            self.config = oci.config.from_file(self.config_file, profile)
            self.identity_client = oci.identity.IdentityClient(self.config)
            self.object_storage_client = oci.object_storage.ObjectStorageClient(self.config)
            
            self.vault_client = oci.vault.VaultsClient(self.config)
            self.secrets_client = oci.secrets.SecretsClient(self.config)
            self.kms_vault_client = oci.key_management.KmsVaultClient(self.config)
            
            self.tenancy_id = self.config['tenancy']
            self.user_id = self.config['user']
            
            self._print_success(f"Successfully authenticated using profile: {profile}")
            if self.verbose:
                self._print_info(f"Config file: {self.config_file}")
                self._print_info(f"Tenancy ID: {self.tenancy_id}")
        except Exception as e:
            self._print_error(f"Authentication failed: {e}")
            sys.exit(1)

    def _print_success(self, message: str):
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {message}")

    def _print_error(self, message: str):
        print(f"{Colors.FAIL}[-]{Colors.ENDC} {message}")

    def _print_info(self, message: str):
        print(f"{Colors.OKBLUE}[*]{Colors.ENDC} {message}")

    def _print_warning(self, message: str):
        print(f"{Colors.WARNING}[!]{Colors.ENDC} {message}")

    def _print_header(self, message: str):
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}{message:^70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.ENDC}\n")

    def enumerate_current_user(self) -> Optional[Dict]:
        self._print_header("CURRENT USER IDENTITY")
        
        try:
            user = self.identity_client.get_user(self.user_id).data
            
            print(f"{Colors.OKCYAN}User Information:{Colors.ENDC}")
            print(f"  Name:        {user.name}")
            print(f"  OCID:        {user.id}")
            print(f"  Description: {user.description if user.description else 'N/A'}")
            print(f"  Email:       {user.email if hasattr(user, 'email') else 'N/A'}")
            print(f"  Status:      {user.lifecycle_state}")
            print(f"  Created:     {user.time_created}")
            
            return user.__dict__
        except Exception as e:
            self._print_error(f"Failed to enumerate user: {e}")
            return None

    def enumerate_groups(self) -> List:
        self._print_header("GROUP ENUMERATION")
        
        try:
            groups = self.identity_client.list_groups(self.tenancy_id).data
            
            if not groups:
                self._print_warning("No groups found")
                return []
            
            self._print_success(f"Found {len(groups)} groups:\n")
            
            for idx, group in enumerate(groups, 1):
                print(f"  {idx}. {Colors.BOLD}{group.name}{Colors.ENDC}")
                print(f"     OCID:        {group.id}")
                print(f"     Description: {group.description if group.description else 'N/A'}")
                print(f"     Status:      {group.lifecycle_state}")
                print()
            
            return [g.__dict__ for g in groups]
        except Exception as e:
            self._print_error(f"Failed to enumerate groups: {e}")
            return []

    def enumerate_user_groups(self) -> List:
        self._print_header("USER GROUP MEMBERSHIPS")
        
        try:
            memberships = self.identity_client.list_user_group_memberships(
                self.tenancy_id,
                user_id=self.user_id
            ).data
            
            if not memberships:
                self._print_warning("User is not a member of any groups")
                return []
            
            self._print_success(f"User is member of {len(memberships)} group(s):\n")
            
            group_info = []
            for idx, membership in enumerate(memberships, 1):
                try:
                    group = self.identity_client.get_group(membership.group_id).data
                    print(f"  {idx}. {Colors.BOLD}{group.name}{Colors.ENDC}")
                    print(f"     OCID:   {group.id}")
                    print(f"     Status: {membership.lifecycle_state}")
                    print()
                    group_info.append({"name": group.name, "id": group.id})
                except Exception as e:
                    self._print_error(f"Failed to get group details: {e}")
            
            return group_info
        except Exception as e:
            self._print_error(f"Failed to enumerate group memberships: {e}")
            return []

    def enumerate_policies(self) -> List:
        self._print_header("IAM POLICY ENUMERATION")
        
        try:
            policies = self.identity_client.list_policies(self.tenancy_id).data
            
            if not policies:
                self._print_warning("No policies found")
                return []
            
            self._print_success(f"Found {len(policies)} policies:\n")
            
            policy_info = []
            for idx, policy in enumerate(policies, 1):
                print(f"  {idx}. {Colors.BOLD}{policy.name}{Colors.ENDC}")
                print(f"     OCID:        {policy.id}")
                print(f"     Description: {policy.description if policy.description else 'N/A'}")
                print(f"     Statements:")
                
                for stmt in policy.statements:
                    if any(danger in stmt.lower() for danger in ['manage', 'all-resources', 'any', 'inspect']):
                        print(f"       {Colors.WARNING}⚠  {stmt}{Colors.ENDC}")
                    else:
                        print(f"       • {stmt}")
                
                print()
                policy_info.append({
                    "name": policy.name,
                    "id": policy.id,
                    "statements": policy.statements
                })
            
            return policy_info
        except Exception as e:
            self._print_error(f"Failed to enumerate policies: {e}")
            return []

    def enumerate_compartments(self) -> List:
        self._print_header("COMPARTMENT ENUMERATION")
        
        try:
            compartments = self.identity_client.list_compartments(self.tenancy_id).data
            
            if not compartments:
                self._print_warning("No compartments found")
                return []
            
            self._print_success(f"Found {len(compartments)} compartments:\n")
            
            for idx, comp in enumerate(compartments, 1):
                print(f"  {idx}. {Colors.BOLD}{comp.name}{Colors.ENDC}")
                print(f"     OCID:        {comp.id}")
                print(f"     Description: {comp.description if comp.description else 'N/A'}")
                print(f"     Status:      {comp.lifecycle_state}")
                print()
            
            return [c.__dict__ for c in compartments]
        except Exception as e:
            self._print_error(f"Failed to enumerate compartments: {e}")
            return []

    def enumerate_vaults(self, compartment_id: Optional[str] = None) -> List:
        self._print_header("VAULT ENUMERATION")
        
        vaults_info = {}
        compartments_to_check = []
        
        if compartment_id:
            compartments_to_check = [{"id": compartment_id, "name": "Specified"}]
        else:
            try:
                comps = self.identity_client.list_compartments(self.tenancy_id).data
                compartments_to_check = [{"id": c.id, "name": c.name} for c in comps]
                compartments_to_check.append({"id": self.tenancy_id, "name": "Root (Tenancy)"})
            except Exception as e:
                self._print_error(f"Failed to list compartments: {e}")
                return []
        
        for comp in compartments_to_check:
            try:
                kms_vaults = self.kms_vault_client.list_vaults(comp["id"]).data
                for v in kms_vaults:
                    vaults_info[v.id] = {
                        "name": v.display_name,
                        "id": v.id,
                        "source": "KMS Management",
                        "state": v.lifecycle_state
                    }
            except Exception as e:
                if self.verbose:
                    self._print_error(f"KMS lookup failed in {comp['name']}")

            try:
                secret_vaults = self.vault_client.list_vaults(comp["id"]).data
                for v in secret_vaults:
                    if v.id not in vaults_info:
                        vaults_info[v.id] = {
                            "name": v.display_name,
                            "id": v.id,
                            "source": "Vault Service",
                            "state": v.lifecycle_state
                        }
            except Exception as e:
                if self.verbose:
                    self._print_error(f"Vault service lookup failed in {comp['name']}")

        if not vaults_info:
            self._print_warning("No accessible vaults found")
        else:
            self._print_success(f"Found {len(vaults_info)} unique accessible vault(s):")
            for idx, (vid, info) in enumerate(vaults_info.items(), 1):
                print(f"  {idx}. {Colors.BOLD}{info['name']}{Colors.ENDC}")
                print(f"     OCID:   {vid}")
                print(f"     Source: {info['source']}")
                print(f"     Status: {info['state']}\n")
        
        return list(vaults_info.values())

    def enumerate_secrets(self, compartment_id: Optional[str] = None, vault_id: Optional[str] = None) -> List:
        self._print_header("SECRET ENUMERATION")
        
        secrets_info = []
        compartments_to_check = []
        
        if compartment_id:
            compartments_to_check = [{"id": compartment_id, "name": "Specified"}]
        else:
            try:
                comps = self.identity_client.list_compartments(self.tenancy_id).data
                compartments_to_check = [{"id": c.id, "name": c.name} for c in comps]
                compartments_to_check.append({"id": self.tenancy_id, "name": "Root (Tenancy)"})
            except Exception as e:
                self._print_error(f"Failed to list compartments: {e}")
                return []
        
        total_secrets = 0
        
        for comp in compartments_to_check:
            try:
                list_secrets_kwargs = {"compartment_id": comp["id"]}
                if vault_id:
                    list_secrets_kwargs["vault_id"] = vault_id
                
                secrets = self.vault_client.list_secrets(**list_secrets_kwargs).data
                
                if secrets:
                    print(f"{Colors.OKCYAN}Compartment: {Colors.BOLD}{comp['name']}{Colors.ENDC}\n")
                    
                    for idx, secret in enumerate(secrets, 1):
                        total_secrets += 1
                        print(f"  {idx}. {Colors.BOLD}{secret.secret_name}{Colors.ENDC}")
                        print(f"     OCID:         {secret.id}")
                        print(f"     Vault ID:     {secret.vault_id}")
                        print(f"     Status:       {secret.lifecycle_state}")
                        
                        if hasattr(secret, 'description') and secret.description:
                            print(f"     Description:  {secret.description}")
                        
                        if hasattr(secret, 'time_created'):
                            print(f"     Created:      {secret.time_created}")
                        
                        if hasattr(secret, 'time_of_current_version_expiry') and secret.time_of_current_version_expiry:
                            print(f"     Expires:      {secret.time_of_current_version_expiry}")
                        
                        print()
                        
                        secrets_info.append({
                            "name": secret.secret_name,
                            "id": secret.id,
                            "vault_id": secret.vault_id,
                            "compartment": comp["name"],
                            "compartment_id": comp["id"],
                            "state": secret.lifecycle_state,
                            "description": secret.description if hasattr(secret, 'description') else None
                        })
            except Exception as e:
                if self.verbose:
                    self._print_error(f"Failed to list secrets in {comp['name']}: {e}")
        
        if total_secrets == 0:
            self._print_warning("No accessible secrets found")
        else:
            self._print_success(f"Found {total_secrets} accessible secret(s)")
        
        return secrets_info

    def get_secret_value(self, secret_id: str, output_file: Optional[str] = None) -> Optional[Dict]:
        self._print_header(f"RETRIEVING SECRET VALUE")
        
        try:
            self._print_info(f"Attempting to retrieve secret: {secret_id}")
            
            secret_bundle = self.secrets_client.get_secret_bundle(secret_id).data
            
            secret_data = {
                "secret_id": secret_id,
                "version_number": secret_bundle.version_number,
                "time_created": str(secret_bundle.time_created) if hasattr(secret_bundle, 'time_created') else None,
                "stages": secret_bundle.stages if hasattr(secret_bundle, 'stages') else None
            }
            
            if hasattr(secret_bundle, 'secret_bundle_content'):
                content = secret_bundle.secret_bundle_content
                
                if hasattr(content, 'content_type'):
                    secret_data["content_type"] = content.content_type
                
                if hasattr(content, 'content'):
                    try:
                        decoded_content = base64.b64decode(content.content).decode('utf-8')
                        secret_data["content"] = decoded_content
                        
                        print(f"\n{Colors.OKGREEN}Secret retrieved successfully!{Colors.ENDC}\n")
                        print(f"{Colors.OKCYAN}Secret Details:{Colors.ENDC}")
                        print(f"  Secret ID:       {secret_id}")
                        print(f"  Version:         {secret_bundle.version_number}")
                        print(f"  Content Type:    {secret_data.get('content_type', 'N/A')}")
                        print(f"\n{Colors.WARNING}Secret Content:{Colors.ENDC}")
                        print(f"  {decoded_content}")
                        print()
                        
                        if output_file:
                            with open(output_file, 'w') as f:
                                f.write(decoded_content)
                            self._print_success(f"Secret content saved to '{output_file}'")
                        
                    except Exception as decode_error:
                        self._print_warning(f"Could not decode secret as UTF-8: {decode_error}")
                        secret_data["content_base64"] = content.content
                        print(f"  Base64 Content: {content.content}")
            
            return secret_data
            
        except oci.exceptions.ServiceError as e:
            if e.status == 404:
                self._print_error(f"Secret not found: {secret_id}")
            elif e.status == 401 or e.status == 403:
                self._print_error(f"Access denied: Insufficient permissions to read secret")
            else:
                self._print_error(f"Service error: {e.message}")
            return None
        except Exception as e:
            self._print_error(f"Failed to retrieve secret: {e}")
            return None

    def enumerate_resources(self, compartment_id: Optional[str] = None) -> Dict:
        self._print_header("RESOURCE ENUMERATION")
        
        resources = {
            "buckets": [],
            "compute_instances": []
        }
        
        try:
            namespace = self.object_storage_client.get_namespace().data
            self._print_info(f"Object Storage Namespace: {namespace}")
        except Exception as e:
            self._print_error(f"Failed to get namespace: {e}")
            return resources
        
        compartments_to_check = []
        if compartment_id:
            compartments_to_check = [{"id": compartment_id, "name": "Specified"}]
        else:
            try:
                comps = self.identity_client.list_compartments(self.tenancy_id).data
                compartments_to_check = [{"id": c.id, "name": c.name} for c in comps]
                compartments_to_check.append({"id": self.tenancy_id, "name": "Root (Tenancy)"})
            except Exception as e:
                self._print_error(f"Failed to list compartments: {e}")
                return resources
        
        print(f"\n{Colors.OKCYAN}Scanning for Object Storage Buckets:{Colors.ENDC}\n")
        
        for comp in compartments_to_check:
            try:
                buckets = self.object_storage_client.list_buckets(
                    namespace,
                    comp["id"]
                ).data
                
                if buckets:
                    print(f"  Compartment: {Colors.BOLD}{comp['name']}{Colors.ENDC}")
                    for bucket in buckets:
                        print(f"    • {bucket.name}")
                        resources["buckets"].append({
                            "name": bucket.name,
                            "compartment": comp["name"],
                            "namespace": namespace
                        })
                    print()
            except Exception as e:
                if self.verbose:
                    self._print_error(f"Failed to list buckets in {comp['name']}: {e}")
        
        if not resources["buckets"]:
            self._print_warning("No accessible buckets found")
        else:
            self._print_success(f"Found {len(resources['buckets'])} accessible bucket(s)")
        
        return resources

    def list_bucket_objects(self, bucket_name: str, namespace: Optional[str] = None) -> List:
        self._print_header(f"LISTING OBJECTS IN BUCKET: {bucket_name}")
        
        if not namespace:
            try:
                namespace = self.object_storage_client.get_namespace().data
            except Exception as e:
                self._print_error(f"Failed to get namespace: {e}")
                return []
        
        try:
            objects = self.object_storage_client.list_objects(
                namespace,
                bucket_name
            ).data.objects
            
            if not objects:
                self._print_warning(f"Bucket '{bucket_name}' is empty")
                return []
            
            self._print_success(f"Found {len(objects)} objects:\n")
            
            object_info = []
            for idx, obj in enumerate(objects, 1):
                if obj.size is not None:
                    size_mb = obj.size / (1024 * 1024)
                    size_display = f"{size_mb:.2f} MB ({obj.size} bytes)"
                else:
                    size_display = "Unknown size"
                
                print(f"  {idx}. {Colors.BOLD}{obj.name}{Colors.ENDC}")
                print(f"     Size:     {size_display}")
                print(f"     Modified: {obj.time_modified}")
                print()
                
                object_info.append({
                    "name": obj.name,
                    "size": obj.size if obj.size is not None else 0,
                    "modified": str(obj.time_modified)
                })
            
            return object_info
        except Exception as e:
            self._print_error(f"Failed to list objects: {e}")
            return []

    def download_object(self, bucket_name: str, object_name: str, destination: str, namespace: Optional[str] = None) -> bool:
        self._print_info(f"Attempting to download '{object_name}' from '{bucket_name}'...")
        
        if not namespace:
            try:
                namespace = self.object_storage_client.get_namespace().data
            except Exception as e:
                self._print_error(f"Failed to get namespace: {e}")
                return False
        
        try:
            object_data = self.object_storage_client.get_object(
                namespace,
                bucket_name,
                object_name
            )
            
            with open(destination, 'wb') as f:
                for chunk in object_data.data.raw.stream(1024 * 1024, decode_content=False):
                    f.write(chunk)
            
            self._print_success(f"Downloaded to '{destination}'")
            return True
        except Exception as e:
            self._print_error(f"Failed to download object: {e}")
            return False

    def analyze_privilege_escalation(self, policies: List) -> None:
        self._print_header("PRIVILEGE ESCALATION ANALYSIS")
        
        dangerous_patterns = {
            "manage": "Full management access",
            "all-resources": "Access to all resources",
            "any {": "Conditional wildcard access",
            "use secret": "Secrets access",
            "read secret": "Secret read access",
            "manage secret": "Secret management access",
            "manage vaults": "Vault management access",
            "manage users": "User management",
            "manage groups": "Group management",
            "manage policies": "Policy management",
            "manage dynamic-groups": "Dynamic group management"
        }
        
        findings = []
        
        for policy in policies:
            for stmt in policy.get("statements", []):
                stmt_lower = stmt.lower()
                for pattern, description in dangerous_patterns.items():
                    if pattern in stmt_lower:
                        if pattern in ["manage", "all-resources", "manage vaults", "manage secret"]:
                            severity = "HIGH"
                        elif pattern in ["use secret", "read secret", "manage users", "manage groups", "manage policies"]:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                        
                        findings.append({
                            "policy": policy["name"],
                            "statement": stmt,
                            "risk": description,
                            "severity": severity
                        })
        
        if not findings:
            self._print_success("No obvious privilege escalation vectors detected")
            return
        
        self._print_warning(f"Found {len(findings)} potential privilege escalation vector(s):\n")
        
        for idx, finding in enumerate(findings, 1):
            if finding["severity"] == "HIGH":
                severity_color = Colors.FAIL
            elif finding["severity"] == "MEDIUM":
                severity_color = Colors.WARNING
            else:
                severity_color = Colors.OKBLUE
                
            print(f"  {idx}. [{severity_color}{finding['severity']}{Colors.ENDC}] {finding['policy']}")
            print(f"     Risk:      {finding['risk']}")
            print(f"     Statement: {finding['statement']}")
            print()

    def export_results(self, results: Dict, filename: str = "oci_enum_results.json"):
        try:
            results["timestamp"] = datetime.now().isoformat()
            results["profile"] = self.profile
            results["tenancy_id"] = self.tenancy_id
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            self._print_success(f"Results exported to '{filename}'")
        except Exception as e:
            self._print_error(f"Failed to export results: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="OCI IAM Enumeration & Privilege Escalation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --user
  %(prog)s --groups
  %(prog)s --user-groups
  %(prog)s --policies
  %(prog)s --resources
  %(prog)s --vaults
  %(prog)s --secrets
  %(prog)s --get-secret ocid1.vaultsecret.oc1...
  %(prog)s --get-secret ocid1.vaultsecret.oc1... --secret-output secret.txt
  %(prog)s --escalation
  %(prog)s --all
  %(prog)s --list-bucket sensitive-data-bucket
  %(prog)s --download sensitive-data-bucket flag.txt output.txt
  %(prog)s --all --profile junior-dev --output results.json
        """
    )
    
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument('-c', '--config', default='~/.oci/config',
                          help='OCI config file path (default: ~/.oci/config)')
    auth_group.add_argument('-p', '--profile', default='DEFAULT',
                          help='OCI config profile to use (default: DEFAULT)')
    
    enum_group = parser.add_argument_group('Enumeration Options')
    enum_group.add_argument('-u', '--user', action='store_true',
                          help='Enumerate current user identity')
    enum_group.add_argument('-g', '--groups', action='store_true',
                          help='Enumerate all groups in tenancy')
    enum_group.add_argument('--user-groups', action='store_true',
                          help='Enumerate current user\'s group memberships')
    enum_group.add_argument('--policies', action='store_true',
                          help='Enumerate IAM policies')
    enum_group.add_argument('-r', '--resources', action='store_true',
                          help='Enumerate accessible resources (buckets, compute, etc)')
    enum_group.add_argument('--compartments', action='store_true',
                          help='Enumerate compartments')
    enum_group.add_argument('-a', '--all', action='store_true',
                          help='Perform full enumeration (including vaults and secrets)')
    
    vault_group = parser.add_argument_group('Vault & Secrets Options')
    vault_group.add_argument('--vaults', action='store_true',
                           help='Enumerate OCI Vaults')
    vault_group.add_argument('--secrets', action='store_true',
                           help='Enumerate secrets in vaults')
    vault_group.add_argument('--get-secret', metavar='SECRET_ID',
                           help='Retrieve value of a specific secret by OCID')
    vault_group.add_argument('--secret-output', metavar='FILE',
                           help='Save secret value to file (use with --get-secret)')
    vault_group.add_argument('--vault-id', metavar='VAULT_ID',
                           help='Filter secrets by specific vault OCID')
    
    analysis_group = parser.add_argument_group('Analysis Options')
    analysis_group.add_argument('-e', '--escalation', action='store_true',
                              help='Analyze privilege escalation vectors')
    
    storage_group = parser.add_argument_group('Object Storage Options')
    storage_group.add_argument('-l', '--list-bucket', metavar='BUCKET',
                             help='List objects in specified bucket')
    storage_group.add_argument('-d', '--download', nargs=3, metavar=('BUCKET', 'OBJECT', 'DEST'),
                             help='Download object: BUCKET OBJECT DESTINATION')
    
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', metavar='FILE',
                            help='Export results to JSON file')
    output_group.add_argument('-v', '--verbose', action='store_true',
                            help='Enable verbose output')
    output_group.add_argument('--no-banner', action='store_true',
                            help='Suppress banner')
    
    args = parser.parse_args()
    
    action_flags = [
        args.all, args.user, args.groups, args.user_groups,
        args.policies, args.compartments, args.resources,
        args.escalation, args.list_bucket, args.download,
        args.vaults, args.secrets, args.get_secret
    ]
    
    if not any(action_flags):
        if not args.no_banner:
            print_banner()
        parser.print_help()
        print(f"\n{Colors.WARNING}[!] No action specified. Use --help for usage information.{Colors.ENDC}\n")
        sys.exit(0)
    
    if not args.no_banner:
        print_banner()
    
    scanner = OCISecurityScanner(
        config_file=args.config,
        profile=args.profile,
        verbose=args.verbose
    )
    
    results = {}
    
    if args.all:
        results["user"] = scanner.enumerate_current_user()
        results["groups"] = scanner.enumerate_groups()
        results["user_groups"] = scanner.enumerate_user_groups()
        results["policies"] = scanner.enumerate_policies()
        results["compartments"] = scanner.enumerate_compartments()
        results["resources"] = scanner.enumerate_resources()
        results["vaults"] = scanner.enumerate_vaults()
        results["secrets"] = scanner.enumerate_secrets()
        
        if results["policies"]:
            scanner.analyze_privilege_escalation(results["policies"])
    else:
        if args.user:
            results["user"] = scanner.enumerate_current_user()
        
        if args.groups:
            results["groups"] = scanner.enumerate_groups()
        
        if args.user_groups:
            results["user_groups"] = scanner.enumerate_user_groups()
        
        if args.policies:
            results["policies"] = scanner.enumerate_policies()
        
        if args.compartments:
            results["compartments"] = scanner.enumerate_compartments()
        
        if args.resources:
            results["resources"] = scanner.enumerate_resources()
        
        if args.vaults:
            results["vaults"] = scanner.enumerate_vaults()
        
        if args.secrets:
            results["secrets"] = scanner.enumerate_secrets(vault_id=args.vault_id)
        
        if args.escalation:
            if not results.get("policies"):
                results["policies"] = scanner.enumerate_policies()
            scanner.analyze_privilege_escalation(results["policies"])
    
    if args.get_secret:
        secret_value = scanner.get_secret_value(args.get_secret, args.secret_output)
        if secret_value:
            results["retrieved_secret"] = secret_value
    
    if args.list_bucket:
        results["bucket_objects"] = scanner.list_bucket_objects(args.list_bucket)
    
    if args.download:
        bucket, obj, dest = args.download
        scanner.download_object(bucket, obj, dest)
    
    if args.output:
        scanner.export_results(results, args.output)
    
    print(f"\n{Colors.OKGREEN}{Colors.BOLD}Scan complete!{Colors.ENDC}\n")

if __name__ == "__main__":
    main()
