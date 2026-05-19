---
title: Prevent XML External Entity (XXE) Injection — Disable DTD Processing
impact: HIGH
impactDescription: XXE enables server-side file disclosure, SSRF, and denial of service through malicious XML documents
tags: xxe, xml, external-entity, dtd, cwe-611
---

## Prevent XML External Entity (XXE) Injection — Disable DTD Processing

XXE injection (CWE-611) exploits XML parsers that process external entity declarations in DTDs. Attackers craft XML payloads that reference local files (`file:///etc/passwd`), internal services (`http://169.254.169.254/`), or recursive entities (billion laughs DoS). 18 high-severity CVEs in the last 6 months (avg CVSS 7.6) with 3 public PoCs, including CVE-2025-66516 (Apache Tika) and CVE-2025-68493 (Apache Struts).

**Incorrect (default XML parser configuration allows external entities):**

```python
import xml.etree.ElementTree as ET
from lxml import etree

# ElementTree: safe by default in Python, but lxml is not
# Malicious XML:
# <?xml version="1.0"?>
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# <user><name>&xxe;</name></user>

def parse_user_xml(xml_string):
    parser = etree.XMLParser()  # lxml default allows external entities
    doc = etree.fromstring(xml_string, parser)
    return doc.find('.//name').text  # Returns contents of /etc/passwd
```

```java
// Java: DocumentBuilderFactory allows DTDs by default
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();  // XXE vulnerable
Document doc = builder.parse(new InputSource(new StringReader(xmlInput)));
```

**Correct (disable DTDs and external entities explicitly):**

```python
from lxml import etree
from defusedxml import ElementTree as SafeET

# Option 1: Use defusedxml (recommended for Python)
def parse_user_xml_safe(xml_string):
    doc = SafeET.fromstring(xml_string)  # Blocks DTDs, entities, externals
    return doc.find('.//name').text

# Option 2: Configure lxml to disable network access and DTDs
def parse_user_xml_lxml(xml_string):
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
    )
    doc = etree.fromstring(xml_string, parser)
    return doc.find('.//name').text
```

```java
// Java: Explicitly disable DTDs and external entities
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
DocumentBuilder builder = factory.newDocumentBuilder();
```

Every XML parser in every language must have external entities disabled explicitly. Default configurations in Java, PHP (`simplexml_load_string`), .NET, and lxml are vulnerable. Use `defusedxml` in Python, JAXP security features in Java, and `libxml_disable_entity_loader(true)` in PHP. If you don't need XML, prefer JSON.
