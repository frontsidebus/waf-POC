# **OpenWebUI Web Application Firewall (WAF) \- v2**

A Python-based reverse proxy for [OpenWebUI](https://github.com/open-webui/open-webui). This tool filters both **Input** (malicious prompts sent to the AI) and **Output** (sensitive data leaking from the AI), providing a secure layer between users and your LLM.

## **Features**

* **Dual-Direction Filtering:**  
  * **Input (Inbound):** Blocks SQL Injection, XSS, and Jailbreak attempts before they reach the backend.  
  * **Output (Outbound):** Scans LLM responses for PII (SSNs, Credit Cards) and sensitive keys.  
* **Response Sanitization:** If sensitive data is detected in the response, the WAF intercepts it and replaces the entire message with a generic, safe template.  
* **Admin Dashboard:** Manage rules, view security logs, and configure the generic response template.  
* **Configurable Scope:** Rules can be set to scan Inputs, Outputs, or Both.

## **Important Note on Streaming**

To effectively scan output for patterns like Credit Card numbers (which might be split across data chunks), **this WAF buffers the entire response** from OpenWebUI before sending it to the user.

* **Trade-off:** You will lose the "typing" effect (streaming). The user will see a loading state until the full response is ready.  
* **Benefit:** Prevents partial leakage of sensitive data.

## **Installation & Usage**

1. **Requirements:**  
   pip install flask requests

2. **Run the WAF:**  
   python waf\_proxy.py

3. **Access:**  
   * **App:** http://localhost:8080  
   * **Admin:** http://localhost:8080/waf-admin

## **Configuration**

### **Managing Rules**

In the Admin Dashboard, when adding a rule, select the **Scope**:

* **Input:** Blocks the request immediately. (Example: DROP TABLE)  
* **Output:** Allows the request, but checks the AI's answer. If it matches, the answer is replaced. (Example: \\d{3}-\\d{2}-\\d{4} for SSN).

### **Changing the Sanitization Message**

1. Go to **Settings** in the Admin UI.  
2. Edit the "Generic Response Template".  
3. This message will be shown to the user whenever an Output rule triggers.

### **Default Rules**

The WAF comes pre-seeded with:

* **Input:** OWASP SQLi, OWASP XSS, System Overrides.  
* **Output:** SSN patterns, Credit Card patterns, API Key regex.