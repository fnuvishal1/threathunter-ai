"""
ThreatHunter AI - Quick Demo & Testing Guide

This script demonstrates how to test the ThreatHunter AI platform
with sample logs and see real results.
"""

import requests
import json
import time

# Configuration
API_URL = "http://localhost:5000/api/analyze"
SAMPLE_LOG_FILE = "sample_logs/windows_security.log"

def print_banner():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║          ThreatHunter AI - Demo Script                     ║
    ║                                                             ║
    ║  This script will upload sample logs and show you          ║
    ║  the real threat detection capabilities!                   ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

def check_server():
    """Check if backend server is running"""
    try:
        response = requests.get("http://localhost:5000/api/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Server Status: ONLINE")
            print(f"   - Sigma Rules: {data['sigma_rules']}")
            print(f"   - MITRE Techniques: {data['mitre_techniques']}")
            print(f"   - AI Enabled: {data['ai_enabled']}\n")
            return True
    except requests.exceptions.RequestException:
        print("❌ Server is OFFLINE")
        print("   Please start the server first:")
        print("   python threathunter_backend.py\n")
        return False

def analyze_sample_log():
    """Upload and analyze sample log file"""
    print("📤 Uploading sample log file...")
    
    try:
        with open(SAMPLE_LOG_FILE, 'rb') as f:
            files = {'files': (SAMPLE_LOG_FILE, f, 'text/plain')}
            response = requests.post(API_URL, files=files, timeout=30)
        
        if response.status_code == 200:
            print("✅ Analysis Complete!\n")
            return response.json()
        else:
            print(f"❌ Error: {response.status_code}")
            return None
    
    except FileNotFoundError:
        print(f"❌ Sample log file not found: {SAMPLE_LOG_FILE}")
        print("   Make sure you're running from the project root directory\n")
        return None
    except Exception as e:
        print(f"❌ Error: {e}\n")
        return None

def display_results(data):
    """Display analysis results in a readable format"""
    if not data or not data.get('success'):
        return
    
    results = data['results'][0]  # Get first file results
    
    print("=" * 70)
    print(" 📊 ANALYSIS RESULTS")
    print("=" * 70)
    
    # Statistics
    stats = results['statistics']
    print(f"\n📈 Statistics:")
    print(f"   Total Log Lines: {stats['total_lines']}")
    print(f"   Threats Detected: {stats['total_threats']}")
    print(f"   - Critical: {stats['critical_threats']}")
    print(f"   - High: {stats['high_threats']}")
    print(f"   Total IOCs: {stats['total_iocs']}")
    print(f"   - Unique IPs: {stats['unique_ips']}")
    print(f"   - Unique Domains: {stats['unique_domains']}")
    
    # Summary
    summary = results['summary']
    print(f"\n🎯 Risk Assessment: {summary['risk_level']}")
    print(f"   {summary['text']}")
    print(f"   Recommendation: {summary['recommendation']}")
    
    # Top Threats
    print(f"\n🚨 Top Detected Threats:")
    for i, threat in enumerate(results['threats'][:5], 1):
        print(f"\n   [{i}] {threat['type']} - {threat['severity']}")
        print(f"       Confidence: {threat['confidence']}%")
        print(f"       Pattern: {threat['matched_pattern'][:60]}...")
        
        if threat.get('mitre'):
            tactics = ", ".join(threat['mitre'].get('tactics', []))
            techniques = ", ".join(threat['mitre'].get('techniques', []))
            print(f"       MITRE: {tactics} ({techniques})")
        
        print(f"       Description: {threat['description'][:80]}...")
    
    # IOCs
    iocs = results['iocs']
    print(f"\n🔍 Extracted IOCs:")
    
    if iocs.get('ips'):
        print(f"   IPs ({len(iocs['ips'])}):")
        for ip in iocs['ips'][:5]:
            print(f"      - {ip}")
        if len(iocs['ips']) > 5:
            print(f"      ... and {len(iocs['ips']) - 5} more")
    
    if iocs.get('domains'):
        print(f"   Domains ({len(iocs['domains'])}):")
        for domain in iocs['domains'][:5]:
            print(f"      - {domain}")
        if len(iocs['domains']) > 5:
            print(f"      ... and {len(iocs['domains']) - 5} more")
    
    if iocs.get('hashes'):
        print(f"   File Hashes ({len(iocs['hashes'])}):")
        for hash_val in iocs['hashes'][:3]:
            print(f"      - {hash_val}")
    
    if iocs.get('commands'):
        print(f"   Suspicious Commands ({len(iocs['commands'])}):")
        for cmd in iocs['commands'][:3]:
            print(f"      - {cmd[:70]}...")
    
    print("\n" + "=" * 70)
    print(" ✅ ANALYSIS COMPLETE")
    print("=" * 70)

def main():
    """Main demo function"""
    print_banner()
    
    # Check if server is running
    if not check_server():
        return
    
    # Analyze sample log
    print("Starting analysis...\n")
    time.sleep(1)
    
    results = analyze_sample_log()
    
    if results:
        display_results(results)
        
        print("\n💡 Next Steps:")
        print("   1. Open http://localhost:5000 in your browser")
        print("   2. Upload your own log files")
        print("   3. Explore the full web interface")
        print("   4. Export reports in PDF/JSON/CSV format")
        print("\n   📚 Check README.md for more information!")
    else:
        print("❌ Demo failed. Please check the errors above.")

if __name__ == "__main__":
    main()
