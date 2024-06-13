from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue
from burp import IExtensionHelpers

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Security Headers Checker")
        callbacks.registerHttpListener(self)
        print("Security Headers Checker extension loaded")
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            response_info = self._helpers.analyzeResponse(response)
            response_headers = response_info.getHeaders()
            headers_to_check = {
                "Strict-Transport-Security": "HTTP Strict Transport Security is an excellent feature to support on your site and strengthens your implementation of TLS by getting the User Agent to enforce the use of HTTPS. Recommended value \"Strict-Transport-Security: max-age=31536000; includeSubDomains\".",
                "Content-Security-Policy": "Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets.",
                "X-Content-Type-Options": "X-Content-Type-Options stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is \"X-Content-Type-Options: nosniff\".",
                "Referrer-Policy": "Referrer Policy is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites.",
                "Permissions-Policy": "Permissions Policy is a new header that allows a site to control which features and APIs can be used in the browser.",
                "X-Frame-Options": "X-Frame-Options can be used to indicate whether or not a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>."
            }
            for header_name, header_description in headers_to_check.items():
                header_present = any(header.lower().startswith(header_name.lower()) for header in response_headers)

                if not header_present:
                    url = messageInfo.getUrl()
                    print("Missing Header: " + header_name)
                    print("URL: " + str(url))
                    http_service = messageInfo.getHttpService()
                    issue_name = "Missing " + header_name + " Header"
                    issue_detail = ("The response from the URL <b>{}</b> is missing the {} header. {}"
                                    .format(url, header_name, header_description))
                    severity = "Low"
                    issue = CustomScanIssue(
                        http_service,
                        url,
                        [self._callbacks.applyMarkers(messageInfo, None, None)],
                        issue_name,
                        issue_detail,
                        severity
                    )
                    self._callbacks.addScanIssue(issue)

        return

class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service
