# **OpenWebUI Web Application Firewall (WAF)**

A lightweight, Python-based reverse proxy designed to sit in front of [OpenWebUI](https://github.com/open-webui/open-webui). It intercepts traffic to filter malicious inputs (SQL injection, XSS, Command Injection) and allows administrators to define custom regex blocking rules via a web interface.

## **Features**

* **Reverse Proxy:** Seamlessly forwards traffic to OpenWebUI while inspecting requests.  
* **Input Filtering:** Blocks requests matching defined security patterns before they reach the LLM or backend.  
* **Admin Dashboard:** A built-in web UI to view logs, toggle rules, and add new custom filters.  
* **OWASP Signatures:** Pre-loaded with basic signatures for common web vulnerabilities (SQLi, XSS, etc.).  
* **Streaming Support:** Supports the streaming nature of LLM responses.

## **Prerequisites**

* Python 3.8+  
* OpenWebUI installed and running (defaulting to port 3000).

## **Installation**

1. Download the WAF:  
   Save the provided python script as waf\_proxy.py.  
2. Install Dependencies:  
   This project requires Flask for the server and Requests for proxying.  
   pip install flask requests

## **Usage**

### **1\. Start OpenWebUI**

Ensure your target application (OpenWebUI) is running. By default, the WAF assumes it is on port 3000\.  
\# Example (if using Docker)  
docker run \-d \-p 3000:8080 ghcr.io/open-webui/open-webui:main

### **2\. Start the WAF**

Run the python script. It will create a local SQLite database (waf\_rules.db) automatically on the first run.  
python waf\_proxy.py

### **3\. Access the Application**

* **User Access:** Point your browser to http://localhost:8080 instead of port 3000\. The WAF will proxy your traffic.  
* **Admin Dashboard:** Manage rules at http://localhost:8080/waf-admin.

## **Configuration**

You can modify the following variables at the top of waf\_proxy.py to match your environment:  
\# The URL where OpenWebUI is actually running  
TARGET\_URL \= "http://localhost:3000" 

\# The port this WAF will listen on  
WAF\_PORT \= 8080

## **Managing Rules**

Navigate to http://localhost:8080/waf-admin.

* **Toggle Rules:** Click the switch next to a rule to enable or disable it instantly.  
* **Add Custom Rules:** \* **Type:** Choose "Regex" for advanced pattern matching or "String" for exact text matching.  
  * **Pattern:** Enter the content you want to block (e.g., internal\_project\_alpha or \\d{3}-\\d{2}-\\d{4} for SSNs).  
* **View Logs:** Check the "Security Logs" tab to see blocked requests, including the IP address and the specific text snippet that triggered the block.

## **Troubleshooting**

* **Connection Error:** If you see a "502 Bad Gateway" or connection error, ensure OpenWebUI is actually running on the TARGET\_URL (port 3000).  
* **False Positives:** If legitimate prompts are being blocked (e.g., asking for code examples involving SQL), go to the Admin Dashboard and disable the specific "OWASP-SQLi" rule, or refine the regex.
