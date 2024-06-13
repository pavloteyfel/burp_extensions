# Security Headers Checker

**Version:** 1.0

## Description

The "Security Headers Checker" extension for Burp Suite is a comprehensive tool designed to enhance web security by identifying the absence of critical HTTP security headers in web application responses. This extension helps security professionals and developers ensure their web applications adhere to best security practices by reporting missing security headers as low severity issues.

![Description](https://github.com/pavloteyfel/burp_extensions/blob/main/images/issues.png)
![Reported Issues](https://github.com/pavloteyfel/burp_extensions/blob/main/images/description.png)



## Features

- **Automated Security Header Checking:** The extension automatically checks for the presence of the following important security headers in HTTP responses:
  - **Strict-Transport-Security (HSTS):** Ensures that the application enforces the use of HTTPS, strengthening the implementation of TLS.
  - **Content-Security-Policy (CSP):** Protects against Cross-Site Scripting (XSS) attacks by whitelisting approved content sources.
  - **X-Content-Type-Options:** Prevents MIME-sniffing by forcing the browser to stick with the declared content-type.
  - **Referrer-Policy:** Controls how much referrer information the browser includes with requests.
  - **Permissions-Policy:** Manages the usage of browser features and APIs to enhance privacy and security.
  - **X-Frame-Options:** Mitigates clickjacking attacks by controlling whether a browser should be allowed to render a page in a frame, iframe, embed, or object.

- **Detailed Issue Reporting:** Missing headers are reported as low severity issues within the Burp Suite "Target" tab. Each issue includes a detailed description of the missing header and its significance:
  - **Strict-Transport-Security:** "HTTP Strict Transport Security is an excellent feature to support on your site and strengthens your implementation of TLS by getting the User Agent to enforce the use of HTTPS. Recommended value 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
  - **Content-Security-Policy:** "Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets."
  - **X-Content-Type-Options:** "X-Content-Type-Options stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is 'X-Content-Type-Options: nosniff'."
  - **Referrer-Policy:** "Referrer Policy is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites."
  - **Permissions-Policy:** "Permissions Policy is a new header that allows a site to control which features and APIs can be used in the browser."
  - **X-Frame-Options:** "X-Frame-Options can be used to indicate whether or not a browser should be allowed to render a page in a `<frame>`, `<iframe>`, `<embed>`, or `<object>`."

## How to Use

1. **Load the Extension:** Save the provided `SecurityHeadersChecker.py` script and load it into Burp Suite via the Extender tab.
2. **Configure Your Browser:** Ensure your browser is configured to use Burp Suite as its proxy.
3. **Browse and Analyze:** Browse the target web application. The extension will automatically analyze HTTP responses and report missing security headers in the Target tab.
4. **Review Issues:** Navigate to the Target tab in Burp Suite and review the reported issues to understand which security headers are missing and their significance.

## Benefits

- **Improved Security Posture:** By ensuring the presence of essential security headers, web applications become more resilient to common web vulnerabilities.
- **Automated Checks:** Reduces the manual effort required to verify the presence of security headers across multiple web applications.
- **Actionable Insights:** Provides detailed descriptions and recommendations for each missing header, aiding developers in implementing necessary security measures.
