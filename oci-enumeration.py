#!/usr/bin/env python3
"""
OCI IAM Enumeration & Privilege Escalation Tool
A professional tool for security testing and IAM assessment in Oracle Cloud Infrastructure

Author: Security Research Team
Version: 1.0.0
License: MIT
"""

import oci
import argparse
import json
import sys
from typing import Dict, List, Optional
from datetime import datetime
import os

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
    """Print tool banner"""
    banner = f"""
{Colors.OKCYAN}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║     ██████╗  ██████╗██╗      ██╗ █████╗ ███╗   ███╗         ║
    ║    ██╔═══██╗██╔════╝██║      ██║██╔══██╗████╗ ████║         ║
    ║    ██║   ██║██║     ██║█████╗██║███████║██╔████╔██║         ║
    ║    ██║   ██║██║     ██║╚════╝██║██╔══██║██║╚██╔╝██║         ║
    ║    ╚██████╔╝╚██████╗██║      ██║██║  ██║██║ ╚═╝ ██║         ║
    ║     ╚═════╝  ╚═════╝╚═╝      ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝         ║
    ║       █████╗ ██╗   ██╗██████╗ ██╗████████╗                  ║
    ║      ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝                  ║
    ║      ███████║██║   ██║██║  ██║██║   ██║                     ║
    ║      ██╔══██║██║   ██║██║  ██║██║   ██║                     ║
    ║      ██║  ██║╚██████╔╝██████╔╝██║   ██║                     ║
    ║      ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝                     ║
    ║                                                              ║
    ║           {Colors.WARNING}⚡ Oracle Cloud IAM Security Scanner ⚡{Colors.OKCYAN}          ║
    ║                                                              ║
    ║               {Colors.ENDC}Version: {Colors.BOLD}1.0.0{Colors.OKCYAN}  |  {Colors.ENDC}License: {Colors.BOLD}MIT{Colors.OKCYAN}            ║
    ║          {Colors.ENDC}For Authorized Security Testing Only{Colors.OKCYAN}               ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
{Colors.ENDC}
    """
    print(banner)

class OCISecurityScanner:
    """Main class for OCI security scanning and enumeration"""
    
    def __init__(self, config_file: str = "~/.oci/config", profile: str = "DEFAULT", verbose: bool = False):
        """Initialize OCI client with configuration"""
        self.verbose = verbose
        self.profile = profile
        self.config_file = os.path.expanduser(config_file)
        
        try:
            self.config = oci.config.from_file(self.config_file, profile)
            self.identity_client = oci.identity.IdentityClient(self.config)
            self.object_storage_client = oci.object_storage.ObjectStorageClient(self.config)
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
        """Print success message"""
        print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {message}")

    def _print_error(self, message: str):
        """Print error message"""
        print(f"{Colors.FAIL}[-]{Colors.ENDC} {message}")

    def _print_info(self, message: str):
        """Print info message"""
        print(f"{Colors.OKBLUE}[*]{Colors.ENDC} {message}")

    def _print_warning(self, message: str):
        """Print warning message"""
        print(f"{Colors.WARNING}[!]{Colors.ENDC} {message}")

    def _print_header(self, message: str):
        """Print section header"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}{message:^70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.ENDC}\n")

    def enumerate_current_user(self) -> Optional[Dict]:
        """Enumerate current user identity"""
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
        """Enumerate all groups in tenancy"""
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
        """Enumerate groups that current user belongs to"""
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
        """Enumerate IAM policies"""
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
        """Enumerate compartments"""
        self._print_header("COMPARTMENT ENUMERATION")
        
        try:
            compartments = self.identity_client.list_compartments(
                self.tenancy_id,
                compartment_id_in_subtree=True
            ).data
            
            if not compartments:
                self._print_warning("No compartments found")
                return []
            
            self._print_success(f"Found {len(compartments)} compartments:\n")
            
            compartment_info = []
            for idx, comp in enumerate(compartments, 1):
                print(f"  {idx}. {Colors.BOLD}{comp.name}{Colors.ENDC}")
                print(f"     OCID:        {comp.id}")
                print(f"     Description: {comp.description if comp.description else 'N/A'}")
                print(f"     Status:      {comp.lifecycle_state}")
                print()
                compartment_info.append({
                    "name": comp.name,
                    "id": comp.id,
                    "state": comp.lifecycle_state
                })
            
            return compartment_info
        except Exception as e:
            self._print_error(f"Failed to enumerate compartments: {e}")
            return []

    def enumerate_resources(self, compartment_id: Optional[str] = None) -> Dict:
        """Enumerate accessible resources (buckets, compute, etc)"""
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
        """List objects in a specific bucket"""
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
                size_mb = obj.size / (1024 * 1024)
                print(f"  {idx}. {Colors.BOLD}{obj.name}{Colors.ENDC}")
                print(f"     Size:     {size_mb:.2f} MB ({obj.size} bytes)")
                print(f"     Modified: {obj.time_modified}")
                print()
                object_info.append({
                    "name": obj.name,
                    "size": obj.size,
                    "modified": str(obj.time_modified)
                })
            
            return object_info
        except Exception as e:
            self._print_error(f"Failed to list objects: {e}")
            return []

    def download_object(self, bucket_name: str, object_name: str, destination: str, namespace: Optional[str] = None) -> bool:
        """Download an object from a bucket"""
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
        """Analyze policies for privilege escalation vectors"""
        self._print_header("PRIVILEGE ESCALATION ANALYSIS")
        
        dangerous_patterns = {
            "manage": "Full management access",
            "all-resources": "Access to all resources",
            "any {": "Conditional wildcard access",
            "use secret": "Secrets access",
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
                        findings.append({
                            "policy": policy["name"],
                            "statement": stmt,
                            "risk": description,
                            "severity": "HIGH" if pattern in ["manage", "all-resources"] else "MEDIUM"
                        })
        
        if not findings:
            self._print_success("No obvious privilege escalation vectors detected")
            return
        
        self._print_warning(f"Found {len(findings)} potential privilege escalation vector(s):\n")
        
        for idx, finding in enumerate(findings, 1):
            severity_color = Colors.FAIL if finding["severity"] == "HIGH" else Colors.WARNING
            print(f"  {idx}. [{severity_color}{finding['severity']}{Colors.ENDC}] {finding['policy']}")
            print(f"     Risk:      {finding['risk']}")
            print(f"     Statement: {finding['statement']}")
            print()

    def export_results(self, results: Dict, filename: str = "oci_enum_results.json"):
        """Export enumeration results to JSON file"""
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
  # Enumerate current user
  %(prog)s --user
  
  # Enumerate groups
  %(prog)s --groups
  
  # Enumerate user's group memberships
  %(prog)s --user-groups
  
  # Enumerate policies
  %(prog)s --policies
  
  # Enumerate accessible resources
  %(prog)s --resources
  
  # Analyze privilege escalation vectors
  %(prog)s --escalation
  
  # Full enumeration
  %(prog)s --all
  
  # List objects in a specific bucket
  %(prog)s --list-bucket sensitive-data-bucket
  
  # Download object from bucket
  %(prog)s --download sensitive-data-bucket flag.txt output.txt
  
  # Use specific profile and export results
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
                          help='Perform full enumeration')
    
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
        args.escalation, args.list_bucket, args.download
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
        
        if args.escalation:
            if not results.get("policies"):
                results["policies"] = scanner.enumerate_policies()
            scanner.analyze_privilege_escalation(results["policies"])
    
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
