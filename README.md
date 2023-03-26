Phish Sticks

Phish Sticks is a Python application that scans phishing emails for malicious URLs using the VirusTotal API. The application is built using the wx Python GUI toolkit and the vt VirusTotal API client library.
Features

The application provides the following features:

    Browse and select an EML file (email message file) to scan for malicious URLs
    Display the subject line of the selected EML file
    Display all URLs in the EML file's body, including those encoded in HTML, and those with the "url" parameter
    Scan each URL using the VirusTotal API, display the VirusTotal analysis statistics for each URL, and indicate whether the URL redirects to another URL
    Copy the subject line, URL, or phishing-forward text to the clipboard with a single click

Usage

To use Phish Sticks, you'll need to do the following:

    Get a VirusTotal API key by signing up for a free VirusTotal Community account at https://www.virustotal.com/gui/join-us
    Replace the VT_API_KEY placeholder with your VirusTotal API key in the vt_api_key variable at the beginning of the phish_sticks.py file
    Install the required Python packages listed in the requirements.txt file using pip install -r requirements.txt
    Run the application by executing the phish_sticks.py file

How it works

Phish Sticks works by using the email Python library to parse the selected EML file, and extracting the URLs from the email body using regular expressions. The application then uses the VirusTotal API to scan each URL and retrieve the analysis statistics for each one. If the URL redirects to another URL, Phish Sticks will scan the final URL and retrieve the analysis statistics for that URL as well.

Once the analysis statistics are retrieved, Phish Sticks displays them in the application's GUI, along with an indication of whether the URL redirects to another URL. The user can then copy the URL, subject line, or phishing-forward text to the clipboard with a single click.
