Next.js RSC RCE Scanner (Burp Suite Extension)
==============================================

A high-fidelity Burp Suite extension to detect the **Next.js / React Server Components (RSC) Remote Code Execution** vulnerability (**CVE-2025-55182** & **CVE-2025-66478**).

This extension implements the detection logic discovered by the [Searchlight Cyber Security Research Team](https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478). It sends a specific malformed multipart request to trigger a property access crash on an `undefined` object within the RSC stream.

Vulnerability Details
---------------------

-   **CVE IDs:** CVE-2025-55182, CVE-2025-66478

-   **Severity:** High / Critical

-   **Affected Software:** Next.js (Default App Router configurations)

-   **Root Cause:** Improper handling of colon-delimited property access in `react-server-dom-parcel`, `react-server-dom-turbopack`, and `react-server-dom-webpack` leads to a server crash (and potential RCE) when processing malicious multipart streams.

Features
--------

-   **High Fidelity:** Checks for the specific RSC error signature (`E{"digest"`) combined with a 500 status code to eliminate false positives.

-   **Active Scanning:** Integrates directly into Burp's Active Scanner.

-   **Manual Scanning:** Right-click any request to explicitly scan for this vulnerability.

-   **Rich Reporting:** Detailed issue dashboard entries with HTML formatting, references, and remediation steps.

-   **Safe Payload:** Uses a detection-only payload that triggers a crash/error without executing harmful code.

Installation
------------

1.  Download the latest JAR file from the Releases page (or build it yourself).

2.  Open **Burp Suite**.

3.  Navigate to **Extensions** > **Installed**.

4.  Click **Add**.

5.  Select **Extension type: Java**.

6.  Select the `NextJsRceScanner-1.0-SNAPSHOT.jar` file.

Usage
-----

1.  Navigate to a target Next.js application in Burp Suite.

2.  Right-click on any request (e.g., `GET /`) in the **Proxy History** or **Repeater**.

3.  Select **Extensions** > **Next.js RSC RCE Scanner** > **Scan**.

4.  Check the **Dashboard** or **Target** tab for issues.

5.  If vulnerable, a **High Severity** issue labeled **"Next.js RSC Remote Code Execution (CVE-2025-55182)"** will appear.

Building from Source
--------------------

To build this project, you need **Java JDK 21+**.

1.  Clone the repository:

    ```
    git clone https://github.com/tobiasGuta/Next.js-RSC-RCE-Scanner-Burp-Suite-Extension.git
    cd Next.js-RSC-RCE-Scanner-Burp-Suite-Extension

    ```

2.  Build with Gradle:

    ```
    # Linux/Mac
    ./gradlew clean build

    # Windows
    gradlew.bat clean build

    ```

3.  Locate the JAR: The compiled extension will be located in: `build/libs/NextJsRceScanner-1.0-SNAPSHOT.jar`

References
----------

-   [Searchlight Cyber: High Fidelity Detection Mechanism](https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478)

-   [Assetnote React2Shell Scanner](https://github.com/assetnote/react2shell-scanner)

-   [Next.js Security Advisory](https://nextjs.org/blog/CVE-2025-66478)

Disclaimer
----------

This tool is for **educational purposes and authorized security testing only**. Do not use this tool on systems you do not have explicit permission to test. The authors are not responsible for any misuse or damage caused by this tool.
