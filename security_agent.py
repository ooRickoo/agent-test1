"""
Security Analysis Agent

A LangChain-powered security analysis tool that combines multiple data sources
with AI-powered analysis to provide comprehensive security assessments.
"""

import os
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
import ipaddress
import socket
import re
import requests
from datetime import datetime
import time
import whois
import shodan
import dns.resolver
import ssl
from OpenSSL import SSL
from urllib.parse import urlparse

# LangChain imports
from langchain_anthropic import ChatAnthropic
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationBufferMemory
from langchain.tools import BaseTool
import json

# Load environment variables
load_dotenv()

def print_section_header(title: str) -> None:
    """Print a formatted section header.
    
    Args:
        title: The title to display in the header
    """
    print("\n" + "="*50)
    print(f" {title} ".center(50, "="))
    print("="*50)

def print_tool_status(tool_name: str, status: str = "running") -> None:
    """Print tool execution status.
    
    Args:
        tool_name: Name of the tool being executed
        status: Current status of the tool
    """
    print(f"🔍 {tool_name}: {status}")

def format_analysis_results(results: Dict[str, Any]) -> str:
    """Format analysis results in a readable way.
    
    Args:
        results: Dictionary containing analysis results
        
    Returns:
        Formatted string representation of results
    """
    output = []
    
    if "error" in results:
        return f"Error: {results['error']}"
    
    # Basic Information
    if "domain" in results:
        output.append(f"Domain: {results['domain']}")
    if "ip" in results:
        output.append(f"IP Address: {results['ip']}")
    if "ip_type" in results:
        output.append(f"IP Type: {results['ip_type']}")
    
    # WHOIS Information
    if "whois_info" in results and results["whois_info"]:
        whois = results["whois_info"]
        if not isinstance(whois, dict) or "error" not in whois:
            output.append("\nWHOIS Information:")
            for key, value in whois.items():
                if value and key != "error":
                    output.append(f"  {key.replace('_', ' ').title()}: {value}")
    
    # DNS Records
    if "dns_records" in results and results["dns_records"]:
        dns = results["dns_records"]
        if not isinstance(dns, dict) or "error" not in dns:
            output.append("\nDNS Records:")
            for record_type, records in dns.items():
                if records and record_type != "error":
                    output.append(f"  {record_type} Records:")
                    for record in records:
                        output.append(f"    - {record}")
    
    # SSL Information
    if "ssl_info" in results and results["ssl_info"]:
        ssl = results["ssl_info"]
        if not isinstance(ssl, dict) or "error" not in ssl:
            output.append("\nSSL Certificate Information:")
            for key, value in ssl.items():
                if value and key != "error":
                    output.append(f"  {key.replace('_', ' ').title()}: {value}")
    
    # Shodan Information
    if "shodan_info" in results and results["shodan_info"]:
        shodan = results["shodan_info"]
        if not isinstance(shodan, dict) or "error" not in shodan:
            output.append("\nShodan Information:")
            for key, value in shodan.items():
                if value and key != "error":
                    if isinstance(value, list):
                        output.append(f"  {key.replace('_', ' ').title()}:")
                        for item in value:
                            output.append(f"    - {item}")
                    else:
                        output.append(f"  {key.replace('_', ' ').title()}: {value}")
    
    # Geolocation
    if "geolocation" in results and results["geolocation"]:
        geo = results["geolocation"]
        if not isinstance(geo, dict) or "error" not in geo:
            output.append("\nGeolocation Information:")
            for key, value in geo.items():
                if value and key != "error":
                    output.append(f"  {key.replace('_', ' ').title()}: {value}")
    
    return "\n".join(output)

def analyze_ip(ip: str) -> Dict[str, Any]:
    """Analyze an IP address using multiple data sources.
    
    Args:
        ip: IP address to analyze
        
    Returns:
        Dictionary containing analysis results
    """
    results = {
        "ip": ip,
        "ip_type": "IPv4" if ":" not in ip else "IPv6",
        "whois_info": {},
        "dns_records": {},
        "ssl_info": {},
        "shodan_info": {},
        "geolocation": {}
    }
    
    try:
        # WHOIS lookup
        print_tool_status("WHOIS Lookup")
        try:
            whois_info = whois.whois(ip)
            results["whois_info"] = {
                "registrar": whois_info.registrar,
                "creation_date": str(whois_info.creation_date),
                "expiration_date": str(whois_info.expiration_date),
                "name_servers": whois_info.name_servers,
                "status": whois_info.status,
                "emails": whois_info.emails,
                "dnssec": whois_info.dnssec
            }
        except Exception as e:
            results["whois_info"] = {"error": str(e)}
        
        # Reverse DNS lookup
        print_tool_status("Reverse DNS Lookup")
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            results["dns_records"] = {
                "reverse_dns": hostname
            }
        except Exception as e:
            results["dns_records"] = {"error": str(e)}
        
        # Shodan lookup
        print_tool_status("Shodan Lookup")
        try:
            api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))
            shodan_info = api.host(ip)
            results["shodan_info"] = {
                "os": shodan_info.get("os"),
                "ports": shodan_info.get("ports", []),
                "hostnames": shodan_info.get("hostnames", []),
                "vulns": shodan_info.get("vulns", []),
                "tags": shodan_info.get("tags", []),
                "isp": shodan_info.get("isp"),
                "org": shodan_info.get("org"),
                "asn": shodan_info.get("asn")
            }
        except Exception as e:
            results["shodan_info"] = {"error": str(e)}
        
        # Geolocation
        print_tool_status("Geolocation Lookup")
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                geo_data = response.json()
                results["geolocation"] = {
                    "country": geo_data.get("country"),
                    "region": geo_data.get("regionName"),
                    "city": geo_data.get("city"),
                    "isp": geo_data.get("isp"),
                    "org": geo_data.get("org"),
                    "as": geo_data.get("as"),
                    "lat": geo_data.get("lat"),
                    "lon": geo_data.get("lon")
                }
        except Exception as e:
            results["geolocation"] = {"error": str(e)}
        
    except Exception as e:
        results["error"] = str(e)
    
    return results

def analyze_domain(domain: str) -> Dict[str, Any]:
    """Analyze a domain using multiple data sources.
    
    Args:
        domain: Domain to analyze
        
    Returns:
        Dictionary containing analysis results
    """
    results = {
        "domain": domain,
        "whois_info": {},
        "dns_records": {},
        "ssl_info": {},
        "shodan_info": {},
        "geolocation": {}
    }
    
    try:
        # WHOIS lookup
        print_tool_status("WHOIS Lookup")
        try:
            whois_info = whois.whois(domain)
            results["whois_info"] = {
                "registrar": whois_info.registrar,
                "creation_date": str(whois_info.creation_date),
                "expiration_date": str(whois_info.expiration_date),
                "name_servers": whois_info.name_servers,
                "status": whois_info.status,
                "emails": whois_info.emails,
                "dnssec": whois_info.dnssec
            }
        except Exception as e:
            results["whois_info"] = {"error": str(e)}
        
        # DNS records
        print_tool_status("DNS Lookup")
        try:
            dns_records = {}
            for record_type in ['A', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    continue
            results["dns_records"] = dns_records
        except Exception as e:
            results["dns_records"] = {"error": str(e)}
        
        # SSL certificate
        print_tool_status("SSL Certificate Check")
        try:
            context = SSL.Context(SSL.TLS_CLIENT_METHOD)
            conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            conn.connect((domain, 443))
            conn.do_handshake()
            cert = conn.get_peer_certificate()
            results["ssl_info"] = {
                "issuer": cert.get_issuer().CN,
                "subject": cert.get_subject().CN,
                "version": cert.get_version(),
                "serial": cert.get_serial_number(),
                "not_before": cert.get_notBefore().decode(),
                "not_after": cert.get_notAfter().decode()
            }
            conn.close()
        except Exception as e:
            results["ssl_info"] = {"error": str(e)}
        
        # Shodan lookup
        print_tool_status("Shodan Lookup")
        try:
            api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))
            shodan_info = api.domain(domain)
            results["shodan_info"] = {
                "tags": shodan_info.get("tags", []),
                "hostnames": shodan_info.get("hostnames", []),
                "vulns": shodan_info.get("vulns", []),
                "subdomains": shodan_info.get("subdomains", []),
                "data": shodan_info.get("data", [])
            }
        except Exception as e:
            results["shodan_info"] = {"error": str(e)}
        
        # Geolocation (using first A record)
        print_tool_status("Geolocation Lookup")
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            if a_records:
                ip = str(a_records[0])
                response = requests.get(f"http://ip-api.com/json/{ip}")
                if response.status_code == 200:
                    geo_data = response.json()
                    results["geolocation"] = {
                        "country": geo_data.get("country"),
                        "region": geo_data.get("regionName"),
                        "city": geo_data.get("city"),
                        "isp": geo_data.get("isp"),
                        "org": geo_data.get("org"),
                        "as": geo_data.get("as"),
                        "lat": geo_data.get("lat"),
                        "lon": geo_data.get("lon")
                    }
        except Exception as e:
            results["geolocation"] = {"error": str(e)}
        
    except Exception as e:
        results["error"] = str(e)
    
    return results

def create_simple_analysis_chain():
    """Create a simple analysis chain using Claude 3 Opus."""
    llm = ChatAnthropic(
        model="claude-3-opus-20240229",
        temperature=0,
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
    )
    
    template = """
    Analyze the following security information and provide a concise summary of the key findings:
    
    {input}
    
    Focus on:
    1. Critical security issues
    2. Infrastructure details
    3. Potential vulnerabilities
    4. Security recommendations
    """
    
    prompt = PromptTemplate(
        input_variables=["input"],
        template=template
    )
    
    return prompt | llm

def create_sequential_analysis_chain():
    """Create a sequential analysis chain using Claude 3 Opus."""
    llm = ChatAnthropic(
        model="claude-3-opus-20240229",
        temperature=0,
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
    )
    
    template = """
    Perform a detailed security analysis of the following information:
    
    {input}
    
    Provide a comprehensive analysis covering:
    1. Domain/IP Information
       - Registration details
       - Infrastructure setup
       - Service configuration
    
    2. Security Assessment
       - SSL/TLS configuration
       - DNS security
       - Known vulnerabilities
       - Security headers
    
    3. Infrastructure Analysis
       - Server details
       - Network configuration
       - Service enumeration
       - Geographic distribution
    
    4. Recommendations
       - Security improvements
       - Best practices
       - Risk mitigation
       - Monitoring suggestions
    """
    
    prompt = PromptTemplate(
        input_variables=["input"],
        template=template
    )
    
    return prompt | llm

def create_chain_with_memory():
    """Create a chain that remembers previous conversations."""
    llm = ChatAnthropic(
        model="claude-3-opus-20240229",
        temperature=0,
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
    )
    
    memory = ConversationBufferMemory(
        memory_key="chat_history",
        return_messages=True
    )
    
    template = """
    Previous conversation:
    {chat_history}
    
    Human: {input}
    Assistant: Let me analyze that for you.
    """
    
    prompt = PromptTemplate(
        input_variables=["chat_history", "input"],
        template=template
    )
    
    return prompt | llm, memory

def process_query(user_input: str, chains: Dict[str, Any]) -> None:
    """Process a user query using the available chains.
    
    Args:
        user_input: The user's query
        chains: Dictionary of available analysis chains
    """
    try:
        print_section_header("Starting Analysis")
        print("Extracting target from query...")
        
        # Extract target from query
        target = None
        
        # Handle "where is" queries
        if "where is" in user_input.lower():
            target = user_input.lower().split("where is")[-1].strip()
            if target.endswith("located?"):
                target = target[:-8].strip()
        
        # Handle domain names
        if not target:
            # Look for domain patterns (e.g., example.com, data-gadgets.com)
            domain_pattern = r'[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}'
            domains = re.findall(domain_pattern, user_input)
            if domains:
                target = domains[0]
        
        # Handle IP addresses if no domain found
        if not target:
            words = user_input.split()
            for word in words:
                try:
                    ipaddress.ip_address(word)
                    target = word
                    break
                except ValueError:
                    continue
        
        if not target:
            print("❌ Could not identify an IP address or domain in your query.")
            return
        
        print(f"✅ Target identified: {target}")
        
        # Perform analysis
        print("\nGathering information...")
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            print_tool_status("IP Analysis")
            analysis_results = analyze_ip(target)
        else:
            print_tool_status("Domain Analysis")
            analysis_results = analyze_domain(target)
        
        # Print raw analysis results
        print("\nGathered Information:")
        print(format_analysis_results(analysis_results))
        
        # Run different types of analysis
        print_section_header("AI Analysis")
        
        print("\nRunning Basic Analysis...")
        simple_analysis = chains["simple"].invoke({"input": str(analysis_results)})
        print("Basic Analysis Results:")
        # Extract just the content from the response
        basic_content = simple_analysis.content if hasattr(simple_analysis, 'content') else str(simple_analysis)
        print(basic_content)
        
        print("\nRunning Detailed Analysis...")
        detailed_analysis = chains["sequential"].invoke({"input": str(analysis_results)})
        print("Detailed Analysis Results:")
        # Extract just the content from the response
        detailed_content = detailed_analysis.content if hasattr(detailed_analysis, 'content') else str(detailed_analysis)
        print(detailed_content)
        
        print("\nRunning Contextual Analysis...")
        # Get the memory object
        memory = chains["memory"][1]
        # Save the current interaction to memory
        memory.save_context({"input": user_input}, {"output": str(analysis_results)})
        # Get the chat history
        chat_history = memory.load_memory_variables({})["chat_history"]
        # Invoke the chain with both input and chat history
        contextual_analysis = chains["memory"][0].invoke({
            "input": user_input,
            "chat_history": chat_history
        })
        print("Contextual Analysis Results:")
        # Extract just the content from the response
        contextual_content = contextual_analysis.content if hasattr(contextual_analysis, 'content') else str(contextual_analysis)
        print(contextual_content)
        
    except Exception as e:
        print(f"❌ Error during analysis: {str(e)}")

def main():
    """Main entry point for the security analysis agent."""
    print_section_header("Security Analysis Tool")
    print("Welcome to the Security Analysis Tool! This tool provides comprehensive security analysis")
    print("of domains and IP addresses using multiple data sources and AI-powered analysis.")
    print("\nYou can analyze:")
    print("  • Known malicious domains and IPs")
    print("  • Suspicious infrastructure")
    print("  • Command & Control servers")
    print("  • Phishing domains")
    print("  • Malware distribution points")
    print("  • Botnet infrastructure")
    print("\nExample queries:")
    print("  - Analyze the security of 185.143.223.12 (Known C2 server)")
    print("  - What can you tell me about 45.95.147.44 (Malware distribution)")
    print("  - Check the security status of 91.92.240.58 (Suspicious activity)")
    print("  - Where is 185.234.72.234 located? (Known malicious IP)")
    print("  - Analyze the security posture of 193.149.176.133 (Botnet infrastructure)")
    print("\nNote: These examples are known malicious IPs/domains from threat intelligence sources.")
    print("They are provided for educational and security research purposes only.")
    print("\nEnter your query (or 'quit' to exit):")
    
    # Create our chains
    print("\nInitializing AI models...")
    chains = {
        "simple": create_simple_analysis_chain(),
        "sequential": create_sequential_analysis_chain(),
        "memory": create_chain_with_memory()
    }
    print("✅ AI models initialized successfully")
    
    while True:
        user_input = input("\n> ").strip()
        
        if user_input.lower() == 'quit':
            break
        
        process_query(user_input, chains)
        
        print_section_header("Analysis Complete")
        print("The analysis has been completed using multiple security tools and sources.")
        print("Review the results above for a comprehensive security assessment.")
        
        print("\nWhat would you like to analyze next?")
        print("Example queries:")
        print("  - Analyze the security of 185.143.223.12 (Known C2 server)")
        print("  - What can you tell me about 45.95.147.44 (Malware distribution)")
        print("  - Check the security status of 91.92.240.58 (Suspicious activity)")
        print("  - Where is 185.234.72.234 located? (Known malicious IP)")
        print("  - Analyze the security posture of 193.149.176.133 (Botnet infrastructure)")
        print("\nEnter your query (or 'quit' to exit):")

if __name__ == "__main__":
    main() 