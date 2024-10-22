import re
import json
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib
from typing import List, Dict, Set

class BrandAlert:
    def __init__(self, alert_type: str, severity: str, details: dict):
        self.timestamp = datetime.now()
        self.alert_type = alert_type
        self.severity = severity
        self.details = details
        self.status = "new"
        
    def to_dict(self):
        return {
            "timestamp": str(self.timestamp),
            "type": self.alert_type,
            "severity": self.severity,
            "details": self.details,
            "status": self.status
        }

class BrandProtectionMonitor:
    def __init__(self, brand_name: str):
        self.brand_name = brand_name
        self.alerts: List[BrandAlert] = []
        self.known_domains: Set[str] = set()
        self.known_accounts: Set[str] = set()
        self.suspicious_keywords = [
            "login", "signin", "account", "password", "verify",
            "support", "help", "service", "official"
        ]
        
    def add_known_domain(self, domain: str):
        """Add legitimate domain to whitelist"""
        self.known_domains.add(domain.lower())
        
    def add_known_account(self, account: str):
        """Add legitimate social media account to whitelist"""
        self.known_accounts.add(account.lower())

class DomainMonitor:
    def __init__(self, brand_monitor: BrandProtectionMonitor):
        self.brand_monitor = brand_monitor
        self.typo_patterns = [
            lambda x: x.replace('o', '0'),
            lambda x: x.replace('i', '1'),
            lambda x: x.replace('l', '1'),
            lambda x: x.replace('e', '3'),
            lambda x: x.replace('a', '4'),
            lambda x: x.replace('s', '5'),
            lambda x: 'my' + x,
            lambda x: x + 'online',
            lambda x: x + 'login',
            lambda x: x + 'official'
        ]
        
    def check_domain(self, domain: str) -> List[BrandAlert]:
        """Check if domain might be impersonating the brand"""
        alerts = []
        domain = domain.lower()
        
        # Skip if it's a known legitimate domain
        if domain in self.brand_monitor.known_domains:
            return alerts
            
        # Check for brand name in domain
        if self.brand_monitor.brand_name.lower() in domain:
            risk_score = self._calculate_domain_risk(domain)
            
            if risk_score > 0.7:
                alerts.append(BrandAlert(
                    "suspicious_domain",
                    "high",
                    {
                        "domain": domain,
                        "risk_score": risk_score,
                        "reason": "High risk domain pattern detected"
                    }
                ))
                
        return alerts
    
    def _calculate_domain_risk(self, domain: str) -> float:
        """Calculate risk score for a domain"""
        risk_score = 0.0
        brand = self.brand_monitor.brand_name.lower()
        
        # Check for suspicious keywords
        for keyword in self.brand_monitor.suspicious_keywords:
            if keyword in domain:
                risk_score += 0.2
                
        # Check for common typosquatting patterns
        for pattern in self.typo_patterns:
            if pattern(brand) in domain:
                risk_score += 0.3
                
        # Check for character substitutions
        substitutions = sum(1 for c in domain if c.isdigit())
        risk_score += substitutions * 0.1
        
        return min(1.0, risk_score)

class SocialMediaMonitor:
    def __init__(self, brand_monitor: BrandProtectionMonitor):
        self.brand_monitor = brand_monitor
        self.impersonation_indicators = [
            "official", "real", "verified", "genuine", "support",
            "help", "team", "staff", "service"
        ]
        
    def check_social_account(self, platform: str, username: str, profile_data: dict) -> List[BrandAlert]:
        """Check if social media account might be impersonating the brand"""
        alerts = []
        username = username.lower()
        
        # Skip known legitimate accounts
        if username in self.brand_monitor.known_accounts:
            return alerts
            
        risk_score = self._calculate_account_risk(username, profile_data)
        
        if risk_score > 0.6:
            alerts.append(BrandAlert(
                "suspicious_account",
                "high" if risk_score > 0.8 else "medium",
                {
                    "platform": platform,
                    "username": username,
                    "risk_score": risk_score,
                    "indicators": self._get_risk_indicators(username, profile_data)
                }
            ))
            
        return alerts
    
    def _calculate_account_risk(self, username: str, profile_data: dict) -> float:
        """Calculate risk score for social media account"""
        risk_score = 0.0
        
        # Check username patterns
        if self.brand_monitor.brand_name.lower() in username:
            risk_score += 0.3
            
        # Check for impersonation indicators in username
        for indicator in self.impersonation_indicators:
            if indicator in username:
                risk_score += 0.2
                
        # Check profile description
        description = profile_data.get('description', '').lower()
        for indicator in self.impersonation_indicators:
            if indicator in description:
                risk_score += 0.15
                
        # Check account age
        creation_date = profile_data.get('created_at', datetime.now())
        if isinstance(creation_date, str):
            creation_date = datetime.fromisoformat(creation_date)
        if datetime.now() - creation_date < timedelta(days=30):
            risk_score += 0.2
            
        return min(1.0, risk_score)
    
    def _get_risk_indicators(self, username: str, profile_data: dict) -> List[str]:
        """Get list of specific risk indicators for an account"""
        indicators = []
        
        if any(indicator in username for indicator in self.impersonation_indicators):
            indicators.append("Suspicious username patterns")
            
        if profile_data.get('verified', False) == False:
            indicators.append("Unverified account")
            
        description = profile_data.get('description', '').lower()
        if any(indicator in description for indicator in self.impersonation_indicators):
            indicators.append("Suspicious profile description")
            
        creation_date = profile_data.get('created_at', datetime.now())
        if isinstance(creation_date, str):
            creation_date = datetime.fromisoformat(creation_date)
        if datetime.now() - creation_date < timedelta(days=30):
            indicators.append("Recently created account")
            
        return indicators

class ContentMonitor:
    def __init__(self, brand_monitor: BrandProtectionMonitor):
        self.brand_monitor = brand_monitor
        self.sensitive_terms = [
            "leak", "breach", "hack", "dump", "database",
            "credentials", "password", "exploit"
        ]
        
    def check_content(self, content: str, source: str) -> List[BrandAlert]:
        """Check content for potential sensitive information leaks"""
        alerts = []
        content_lower = content.lower()
        
        if self.brand_monitor.brand_name.lower() in content_lower:
            risk_score = self._calculate_content_risk(content_lower)
            
            if risk_score > 0.5:
                alerts.append(BrandAlert(
                    "sensitive_content",
                    "high" if risk_score > 0.8 else "medium",
                    {
                        "source": source,
                        "risk_score": risk_score,
                        "matches": self._get_sensitive_matches(content_lower),
                        "excerpt": self._get_relevant_excerpt(content, content_lower)
                    }
                ))
                
        return alerts
    
    def _calculate_content_risk(self, content: str) -> float:
        """Calculate risk score for content"""
        risk_score = 0.0
        
        # Check for sensitive terms
        for term in self.sensitive_terms:
            if term in content:
                risk_score += 0.25
                
        # Check for potential credentials
        if re.search(r'\b[\w\.-]+@[\w\.-]+\.\w+\b', content):  # email pattern
            risk_score += 0.3
            
        if re.search(r'\b\d{16}\b', content):  # potential card number
            risk_score += 0.4
            
        return min(1.0, risk_score)
    
    def _get_sensitive_matches(self, content: str) -> List[str]:
        """Get list of sensitive terms found in content"""
        return [term for term in self.sensitive_terms if term in content]
    
    def _get_relevant_excerpt(self, content: str, content_lower: str) -> str:
        """Get relevant excerpt around sensitive content"""
        brand_pos = content_lower.find(self.brand_monitor.brand_name.lower())
        if brand_pos >= 0:
            start = max(0, brand_pos - 50)
            end = min(len(content), brand_pos + 50)
            return content[start:end]
        return ""

def main():
    # Example usage
    monitor = BrandProtectionMonitor("ExampleCorp")
    
    # Add known legitimate domains/accounts
    monitor.add_known_domain("examplecorp.com")
    monitor.add_known_account("@examplecorp")
    
    # Initialize monitors
    domain_monitor = DomainMonitor(monitor)
    social_monitor = SocialMediaMonitor(monitor)
    content_monitor = ContentMonitor(monitor)
    
    # Example checks
    print("Checking suspicious domain...")
    alerts = domain_monitor.check_domain("examplecorp-support-login.com")
    for alert in alerts:
        print(json.dumps(alert.to_dict(), indent=2))
        
    print("\nChecking suspicious social account...")
    profile_data = {
        "description": "Official ExampleCorp Support Team",
        "created_at": (datetime.now() - timedelta(days=7)).isoformat(),
        "verified": False
    }
    alerts = social_monitor.check_social_account("twitter", "examplecorp_support", profile_data)
    for alert in alerts:
        print(json.dumps(alert.to_dict(), indent=2))
        
    print("\nChecking suspicious content...")
    content = "Found database dump containing ExampleCorp customer credentials"
    alerts = content_monitor.check_content(content, "forum_post")
    for alert in alerts:
        print(json.dumps(alert.to_dict(), indent=2))

if __name__ == "__main__":
    main()