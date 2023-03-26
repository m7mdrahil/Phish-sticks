Phish Sticks

Phish Sticks is a Python application that scans URLs in EML files using VirusTotal API to check if they are phishing links or not.
Prerequisites

    Python 3.x
    wxPython
    requests
    VirusTotal API key

Installation

    Clone this repository to your local machine.

    Install the required packages using pip.

    pip install wxpython requests vt

    Replace the VT_API_KEY in the code with your VirusTotal API key.

Usage

    Run the phish_sticks.py file.
    Browse for an EML file.
    Click on the Get URLs button to extract URLs from the EML file.
    Click on a URL to scan it using VirusTotal.
    The scan results will be displayed on the right side of the application.
    You can click on the Copy Link button to copy the URL to the clipboard.
    You can click on the Copy Subject button to copy the subject of the EML file to the clipboard.
    You can click on the Phish Forward button to copy a message to the clipboard that can be used to forward the EML file to someone with a warning that it may contain phishing links.
