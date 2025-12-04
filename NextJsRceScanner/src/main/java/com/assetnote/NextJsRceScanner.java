package com.assetnote;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;

public class NextJsRceScanner implements BurpExtension, ScanCheck {

    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Next.js RSC RCE Scanner (CVE-2025-55182)");
        api.scanner().registerScanCheck(this);
        api.logging().logToOutput("Next.js RSC Scanner loaded (v2.0 - Rich Reporting)");
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        return doCheck(baseRequestResponse.request());
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        return AuditResult.auditResult(new ArrayList<>());
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.name().equals(existingIssue.name()) ?
                ConsolidationAction.KEEP_EXISTING :
                ConsolidationAction.KEEP_BOTH;
    }

    /**
     * Helper method to generate the rich HTML report for the Dashboard.
     */
    private AuditIssue createIssue(HttpRequest baseRequest, HttpRequestResponse evidence) {
        // 1. Construct the Issue Detail (The "What happened")
        String issueDetail = new StringBuilder()
                .append("The application responded with a <b>HTTP 500 Internal Server Error</b> containing the specific React Server Components (RSC) error signature: <b>E{\"digest\"</b>.<br><br>")
                .append("This confirms that the server crashed while attempting to access a property on an <code>undefined</code> object during RSC stream processing. ")
                .append("This specific crash is the indicator of compromise for <b>CVE-2025-55182</b> (and the related CVE-2025-66478), allowing for Remote Code Execution (RCE).")
                .toString();

        // 2. Construct the Background (The "References")
        String issueBackground = new StringBuilder()
                .append("<b>Vulnerability Information:</b><br>")
                .append("This vulnerability affects default configurations of Next.js using the App Router. It allows an unauthenticated attacker to execute arbitrary code on the server by sending a malformed multipart request that triggers a property access on an undefined object in the <code>react-server-dom-webpack</code> package.<br><br>")
                .append("<b>References:</b><ul>")
                .append("<li><a href='https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478'>Searchlight Cyber: High Fidelity Detection Mechanism</a></li>")
                .append("<li><a href='https://nvd.nist.gov/vuln/detail/CVE-2025-55182'>NVD: CVE-2025-55182 Detail</a></li>")
                .append("<li><a href='https://nextjs.org/blog/CVE-2025-66478'>Next.js Security Advisory (CVE-2025-66478)</a></li>")
                .append("</ul>")
                .toString();

        // 3. Create the Issue object
        return AuditIssue.auditIssue(
                "Next.js RSC Remote Code Execution (CVE-2025-55182)", // Name
                issueDetail,                                         // Detail (HTML supported)
                "Upgrade to the latest version of Next.js immediately (e.g., v15.0.4+ or v14.2.19+).", // Remediation
                baseRequest.url(),                                   // URL
                AuditIssueSeverity.HIGH,                             // Severity
                AuditIssueConfidence.CERTAIN,                        // Confidence
                issueBackground,                                     // Background (HTML supported)
                null,                                                // Remediation Background
                AuditIssueSeverity.HIGH,                             // Typical Severity
                evidence                                             // Http Evidence
        );
    }

    private AuditResult doCheck(HttpRequest baseRequest) {
        api.logging().logToOutput("[-] Starting check for: " + baseRequest.url());

        // 1. Prepare Body Payload
        String bodyString =
                "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" +
                        "Content-Disposition: form-data; name=\"1\"\r\n\r\n" +
                        "{}\r\n" +
                        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" +
                        "Content-Disposition: form-data; name=\"0\"\r\n\r\n" +
                        "[\"$1:a:a\"]\r\n" +
                        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--";

        // 2. Transform the Base Request (Safe Modification)
        HttpRequest exploitRequest = baseRequest
                .withMethod("POST")
                .withBody(ByteArray.byteArray(bodyString));

        // 3. Clean up conflicting headers
        exploitRequest = exploitRequest.withRemovedHeader("Content-Type");
        exploitRequest = exploitRequest.withRemovedHeader("Content-Length");
        exploitRequest = exploitRequest.withRemovedHeader("Next-Action");
        exploitRequest = exploitRequest.withRemovedHeader("Next-Router-State-Tree");
        exploitRequest = exploitRequest.withRemovedHeader("X-Nextjs-Request-Id");
        exploitRequest = exploitRequest.withRemovedHeader("X-Nextjs-Html-Request-Id");

        // 4. Add the Specific Exploit Headers
        exploitRequest = exploitRequest.withHeader(HttpHeader.httpHeader("Next-Action", "x"));
        exploitRequest = exploitRequest.withHeader(HttpHeader.httpHeader("X-Nextjs-Request-Id", "b5dce965"));
        exploitRequest = exploitRequest.withHeader(HttpHeader.httpHeader("Next-Router-State-Tree", "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"));
        exploitRequest = exploitRequest.withHeader(HttpHeader.httpHeader("X-Nextjs-Html-Request-Id", "SSTMXm7OJ_g0Ncx6jpQt9"));

        String boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
        exploitRequest = exploitRequest.withHeader(HttpHeader.httpHeader("Content-Type", "multipart/form-data; boundary=" + boundary));

        // 5. Send Request
        api.logging().logToOutput("[-] Sending exploit payload...");
        HttpRequestResponse checkRequestResponse = api.http().sendRequest(exploitRequest);
        HttpResponse response = checkRequestResponse.response();

        // 6. Debug Output
        api.logging().logToOutput("[-] Status Code: " + response.statusCode());

        // 7. Check for Vulnerability
        if (response.statusCode() == 500 && response.bodyToString().contains("E{\"digest\"")) {

            api.logging().logToOutput("[!] VULNERABILITY CONFIRMED! Creating rich report...");

            AuditIssue issue = createIssue(baseRequest, checkRequestResponse);

            return AuditResult.auditResult(List.of(issue));
        }

        return AuditResult.auditResult(new ArrayList<>());
    }
}