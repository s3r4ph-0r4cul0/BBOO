#!/usr/bin/env python3
"""
Intelligent Nmap Agent with Parameter Inference
Developed by Manus AI
"""

import nmap
import json
import datetime
import os
import sys
import argparse
import threading
import time
import re
import ipaddress
from typing import Dict, List, Optional, Any, Tuple
import socket

class IntelligentNmapAgent:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_profiles = {
            'quick': {
                'name': 'Quick Scan',
                'args': '-F -T4 --max-retries 1',
                'description': 'Fast scan of the most common 100 ports',
                'use_cases': ['initial_reconnaissance', 'quick_check', 'time_limited']
            },
            'comprehensive': {
                'name': 'Comprehensive Scan',
                'args': '-p- -sV -sC -O -T4',
                'description': 'Complete scan with service detection and OS fingerprinting',
                'use_cases': ['detailed_analysis', 'security_audit', 'full_assessment']
            },
            'stealth': {
                'name': 'Stealth Scan',
                'args': '-sS -T2 -f',
                'description': 'Stealthy SYN scan with slow timing and fragmentation',
                'use_cases': ['evasion', 'ids_avoidance', 'covert_scan']
            },
            'vulnerability': {
                'name': 'Vulnerability Scan',
                'args': '--script vuln -sV',
                'description': 'Vulnerability detection with service version detection',
                'use_cases': ['vulnerability_assessment', 'security_testing', 'compliance_check']
            },
            'web': {
                'name': 'Web Services Scan',
                'args': '-p 80,443,8080,8443 -sV --script "http-* and not(dos or brute)"',
                'description': 'Focused scan for web services with HTTP scripts',
                'use_cases': ['web_application_testing', 'http_service_analysis', 'web_security']
            },
            'discovery': {
                'name': 'Host Discovery',
                'args': '-sn',
                'description': 'Ping sweep to discover active hosts',
                'use_cases': ['network_mapping', 'host_enumeration', 'network_discovery']
            },
            'port_specific': {
                'name': 'Port-Specific Scan',
                'args': '-sV -sC',
                'description': 'Targeted scan for specific ports with service detection',
                'use_cases': ['service_analysis', 'targeted_assessment', 'specific_service_check']
            }
        }
        
        self.scan_history = []
        self.network_context = {}
        
    def analyze_target(self, target: str) -> Dict[str, Any]:
        """Analyze target to understand its characteristics"""
        analysis = {
            'target_type': 'unknown',
            'is_network_range': False,
            'estimated_hosts': 1,
            'is_local': False,
            'is_private': False,
            'domain_info': None,
            'port_hints': []
        }
        
        try:
            # Check if it's an IP address or network range
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                analysis['target_type'] = 'network'
                analysis['is_network_range'] = True
                analysis['estimated_hosts'] = network.num_addresses
                analysis['is_private'] = network.is_private
                analysis['is_local'] = network.is_loopback or str(network.network_address).startswith('192.168.') or str(network.network_address).startswith('10.') or str(network.network_address).startswith('172.')
            else:
                try:
                    ip = ipaddress.ip_address(target)
                    analysis['target_type'] = 'ip'
                    analysis['is_private'] = ip.is_private
                    analysis['is_local'] = ip.is_loopback or str(ip).startswith('192.168.') or str(ip).startswith('10.') or str(ip).startswith('172.')
                except ValueError:
                    # It's likely a hostname/domain
                    analysis['target_type'] = 'hostname'
                    analysis['domain_info'] = self._analyze_domain(target)
                    
                    # Try to resolve to get IP info
                    try:
                        resolved_ip = socket.gethostbyname(target)
                        ip = ipaddress.ip_address(resolved_ip)
                        analysis['is_private'] = ip.is_private
                        analysis['is_local'] = ip.is_loopback
                    except:
                        pass
        except Exception as e:
            print(f"Error analyzing target: {e}")
        
        return analysis
    
    def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain characteristics"""
        domain_info = {
            'tld': None,
            'subdomain_count': 0,
            'likely_service_type': 'unknown'
        }
        
        parts = domain.split('.')
        if len(parts) > 1:
            domain_info['tld'] = parts[-1]
            domain_info['subdomain_count'] = len(parts) - 2
            
            # Analyze for common service patterns
            domain_lower = domain.lower()
            if any(keyword in domain_lower for keyword in ['mail', 'smtp', 'pop', 'imap']):
                domain_info['likely_service_type'] = 'mail'
            elif any(keyword in domain_lower for keyword in ['web', 'www', 'api', 'app']):
                domain_info['likely_service_type'] = 'web'
            elif any(keyword in domain_lower for keyword in ['ftp', 'file']):
                domain_info['likely_service_type'] = 'file'
            elif any(keyword in domain_lower for keyword in ['db', 'database', 'sql']):
                domain_info['likely_service_type'] = 'database'
        
        return domain_info
    
    def infer_scan_parameters(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Intelligently infer the best scan parameters based on target analysis"""
        
        # Analyze the target
        target_analysis = self.analyze_target(target)
        
        # Initialize inference result
        inference = {
            'recommended_profile': 'quick',
            'custom_ports': None,
            'timing_template': 'T4',
            'additional_scripts': [],
            'reasoning': [],
            'confidence': 0.0,
            'estimated_duration': '1-2 minutes'
        }
        
        confidence_factors = []
        
        # Network range considerations
        if target_analysis['is_network_range']:
            if target_analysis['estimated_hosts'] > 100:
                inference['recommended_profile'] = 'discovery'
                inference['timing_template'] = 'T3'
                inference['reasoning'].append("Large network range detected - using host discovery first")
                confidence_factors.append(0.9)
                inference['estimated_duration'] = f"{target_analysis['estimated_hosts'] // 50}-{target_analysis['estimated_hosts'] // 25} minutes"
            elif target_analysis['estimated_hosts'] > 10:
                inference['recommended_profile'] = 'quick'
                inference['timing_template'] = 'T4'
                inference['reasoning'].append("Medium network range - using quick scan")
                confidence_factors.append(0.8)
                inference['estimated_duration'] = f"{target_analysis['estimated_hosts'] // 10}-{target_analysis['estimated_hosts'] // 5} minutes"
        
        # Local vs remote considerations
        if target_analysis['is_local']:
            inference['timing_template'] = 'T5'
            inference['reasoning'].append("Local target detected - using aggressive timing")
            confidence_factors.append(0.8)
        elif not target_analysis['is_private']:
            inference['timing_template'] = 'T3'
            inference['reasoning'].append("External target - using moderate timing to avoid detection")
            confidence_factors.append(0.7)
        
        # Domain-based inference
        if target_analysis['target_type'] == 'hostname' and target_analysis['domain_info']:
            domain_info = target_analysis['domain_info']
            
            if domain_info['likely_service_type'] == 'web':
                inference['recommended_profile'] = 'web'
                inference['custom_ports'] = '80,443,8080,8443,3000,5000,8000,9000'
                inference['reasoning'].append("Web service domain detected - focusing on HTTP/HTTPS ports")
                confidence_factors.append(0.9)
            elif domain_info['likely_service_type'] == 'mail':
                inference['custom_ports'] = '25,110,143,465,587,993,995'
                inference['additional_scripts'] = ['smtp-enum-users', 'pop3-capabilities', 'imap-capabilities']
                inference['reasoning'].append("Mail service domain detected - focusing on email ports")
                confidence_factors.append(0.85)
            elif domain_info['likely_service_type'] == 'ftp':
                inference['custom_ports'] = '21,22,990'
                inference['additional_scripts'] = ['ftp-anon', 'ftp-bounce']
                inference['reasoning'].append("FTP service domain detected - focusing on file transfer ports")
                confidence_factors.append(0.8)
        
        # Context-based inference
        if context:
            if context.get('purpose') == 'security_audit':
                inference['recommended_profile'] = 'vulnerability'
                inference['reasoning'].append("Security audit context - using vulnerability scan")
                confidence_factors.append(0.9)
            elif context.get('purpose') == 'network_mapping':
                inference['recommended_profile'] = 'discovery'
                inference['reasoning'].append("Network mapping context - using host discovery")
                confidence_factors.append(0.85)
            elif context.get('stealth_required'):
                inference['recommended_profile'] = 'stealth'
                inference['timing_template'] = 'T2'
                inference['reasoning'].append("Stealth requirement - using slow, evasive scan")
                confidence_factors.append(0.8)
            elif context.get('time_limited'):
                inference['recommended_profile'] = 'quick'
                inference['timing_template'] = 'T5'
                inference['reasoning'].append("Time constraint - using fastest scan profile")
                confidence_factors.append(0.7)
        
        # Historical context
        if self.scan_history:
            recent_scans = [scan for scan in self.scan_history[-5:] if scan.get('target') == target]
            if recent_scans:
                last_scan = recent_scans[-1]
                if last_scan.get('status') == 'completed' and 'results' in last_scan:
                    # Analyze previous results to refine approach
                    results = last_scan['results']
                    if results['summary']['open_ports'] > 10:
                        inference['recommended_profile'] = 'comprehensive'
                        inference['reasoning'].append("Previous scan found many open ports - using comprehensive scan")
                        confidence_factors.append(0.8)
        
        # Calculate overall confidence
        if confidence_factors:
            inference['confidence'] = sum(confidence_factors) / len(confidence_factors)
        else:
            inference['confidence'] = 0.5  # Default moderate confidence
        
        # Ensure we have at least one reasoning
        if not inference['reasoning']:
            inference['reasoning'].append("Using default quick scan profile")
            inference['confidence'] = 0.5
        
        return inference
    
    def build_nmap_command(self, target: str, inference: Dict[str, Any]) -> str:
        """Build the complete nmap command based on inference"""
        
        profile = inference['recommended_profile']
        base_args = self.scan_profiles[profile]['args']
        
        # Start with base arguments
        args_parts = base_args.split()
        
        # Add timing template if different from default
        timing = inference.get('timing_template', 'T4')
        if f'-{timing}' not in base_args:
            # Remove existing timing template
            args_parts = [arg for arg in args_parts if not re.match(r'-T[0-5]', arg)]
            args_parts.append(f'-{timing}')
        
        # Add custom ports if specified
        if inference.get('custom_ports'):
            # Remove existing port specification
            args_parts = [arg for arg in args_parts if not arg.startswith('-p')]
            args_parts.extend(['-p', inference['custom_ports']])
        
        # Add additional scripts
        if inference.get('additional_scripts'):
            existing_scripts = []
            for i, arg in enumerate(args_parts):
                if arg == '--script' and i + 1 < len(args_parts):
                    existing_scripts = args_parts[i + 1].split(',')
                    break
            
            all_scripts = existing_scripts + inference['additional_scripts']
            if all_scripts:
                # Remove existing script specification
                new_args = []
                skip_next = False
                for i, arg in enumerate(args_parts):
                    if skip_next:
                        skip_next = False
                        continue
                    if arg == '--script':
                        skip_next = True
                        continue
                    new_args.append(arg)
                
                new_args.extend(['--script', ','.join(all_scripts)])
                args_parts = new_args
        
        return ' '.join(args_parts)
    
    def execute_intelligent_scan(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute scan with intelligent parameter inference"""
        
        # Perform inference
        inference = self.infer_scan_parameters(target, context)
        
        # Build command
        nmap_args = self.build_nmap_command(target, inference)
        
        # Prepare scan info
        scan_info = {
            'target': target,
            'inference': inference,
            'nmap_args': nmap_args,
            'start_time': datetime.datetime.now(),
            'status': 'running'
        }
        
        try:
            print(f"Executing intelligent scan...")
            print(f"Target: {target}")
            print(f"Inferred profile: {inference['recommended_profile']}")
            print(f"Confidence: {inference['confidence']:.2f}")
            print(f"Reasoning: {'; '.join(inference['reasoning'])}")
            print(f"Estimated duration: {inference['estimated_duration']}")
            print(f"Nmap command: nmap {nmap_args} {target}")
            print("-" * 60)
            
            # Execute the scan
            self.nm.scan(target, arguments=nmap_args)
            
            # Process results
            results = self._process_scan_results()
            
            scan_info.update({
                'end_time': datetime.datetime.now(),
                'status': 'completed',
                'results': results
            })
            
        except Exception as e:
            scan_info.update({
                'end_time': datetime.datetime.now(),
                'status': 'error',
                'error': str(e)
            })
            raise
        
        self.scan_history.append(scan_info)
        return scan_info
    
    def _process_scan_results(self) -> Dict:
        """Process and format scan results"""
        results = {
            'hosts': [],
            'summary': {
                'total_hosts': 0,
                'hosts_up': 0,
                'total_ports': 0,
                'open_ports': 0
            }
        }
        
        for host in self.nm.all_hosts():
            host_info = {
                'ip': host,
                'hostname': self.nm[host].hostname(),
                'state': self.nm[host].state(),
                'protocols': {}
            }
            
            results['summary']['total_hosts'] += 1
            if host_info['state'] == 'up':
                results['summary']['hosts_up'] += 1
            
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                host_info['protocols'][proto] = []
                
                for port in ports:
                    port_info = {
                        'port': port,
                        'state': self.nm[host][proto][port]['state'],
                        'name': self.nm[host][proto][port].get('name', ''),
                        'product': self.nm[host][proto][port].get('product', ''),
                        'version': self.nm[host][proto][port].get('version', ''),
                        'extrainfo': self.nm[host][proto][port].get('extrainfo', '')
                    }
                    
                    host_info['protocols'][proto].append(port_info)
                    results['summary']['total_ports'] += 1
                    
                    if port_info['state'] == 'open':
                        results['summary']['open_ports'] += 1
            
            results['hosts'].append(host_info)
        
        return results
    
    def explain_inference(self, target: str, context: Dict[str, Any] = None) -> str:
        """Provide detailed explanation of parameter inference"""
        
        inference = self.infer_scan_parameters(target, context)
        target_analysis = self.analyze_target(target)
        
        explanation = []
        explanation.append("=== INTELLIGENT SCAN PARAMETER INFERENCE ===")
        explanation.append(f"Target: {target}")
        explanation.append("")
        
        explanation.append("TARGET ANALYSIS:")
        explanation.append(f"  Type: {target_analysis['target_type']}")
        explanation.append(f"  Network Range: {target_analysis['is_network_range']}")
        if target_analysis['is_network_range']:
            explanation.append(f"  Estimated Hosts: {target_analysis['estimated_hosts']}")
        explanation.append(f"  Local Target: {target_analysis['is_local']}")
        explanation.append(f"  Private Network: {target_analysis['is_private']}")
        
        if target_analysis.get('domain_info'):
            domain_info = target_analysis['domain_info']
            explanation.append(f"  Domain TLD: {domain_info['tld']}")
            explanation.append(f"  Likely Service: {domain_info['likely_service_type']}")
        
        explanation.append("")
        explanation.append("INFERENCE RESULTS:")
        explanation.append(f"  Recommended Profile: {inference['recommended_profile']}")
        explanation.append(f"  Confidence Level: {inference['confidence']:.2f}")
        explanation.append(f"  Timing Template: {inference['timing_template']}")
        explanation.append(f"  Estimated Duration: {inference['estimated_duration']}")
        
        if inference.get('custom_ports'):
            explanation.append(f"  Custom Ports: {inference['custom_ports']}")
        
        if inference.get('additional_scripts'):
            explanation.append(f"  Additional Scripts: {', '.join(inference['additional_scripts'])}")
        
        explanation.append("")
        explanation.append("REASONING:")
        for i, reason in enumerate(inference['reasoning'], 1):
            explanation.append(f"  {i}. {reason}")
        
        explanation.append("")
        explanation.append(f"FINAL COMMAND: nmap {self.build_nmap_command(target, inference)} {target}")
        
        return "\n".join(explanation)

def main():
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(description='Intelligent Nmap Agent with Parameter Inference')
    parser.add_argument('target', help='Target to scan (IP, hostname, or network range)')
    parser.add_argument('--explain', action='store_true', help='Explain parameter inference without scanning')
    parser.add_argument('--context', help='JSON string with scan context (purpose, stealth_required, time_limited)')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    # Parse context if provided
    context = None
    if args.context:
        try:
            context = json.loads(args.context)
        except json.JSONDecodeError:
            print("Error: Invalid JSON in context parameter")
            sys.exit(1)
    
    # Create agent
    agent = IntelligentNmapAgent()
    
    if args.explain:
        # Just explain the inference
        explanation = agent.explain_inference(args.target, context)
        print(explanation)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(explanation)
            print(f"\nExplanation saved to {args.output}")
    else:
        # Execute the scan
        try:
            scan_result = agent.execute_intelligent_scan(args.target, context)
            
            # Print summary
            if scan_result['status'] == 'completed':
                results = scan_result['results']
                print("\n=== SCAN COMPLETED ===")
                print(f"Hosts found: {results['summary']['hosts_up']}/{results['summary']['total_hosts']}")
                print(f"Open ports: {results['summary']['open_ports']}/{results['summary']['total_ports']}")
                print(f"Duration: {scan_result['end_time'] - scan_result['start_time']}")
                
                # Save results if requested
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump(scan_result, f, indent=2, default=str)
                    print(f"Results saved to {args.output}")
            else:
                print(f"Scan failed: {scan_result.get('error', 'Unknown error')}")
                sys.exit(1)
                
        except Exception as e:
            print(f"Error executing scan: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()

