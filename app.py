import wx
import re
import glob
from urllib.parse import unquote
import pyperclip
from email.parser import BytesParser
from email import policy
import email
import vt
import requests
import base64

vt_api_key = 'VT_API_KEY'
client = vt.Client(vt_api_key)

def phish_fwd_cp():
    result = "Phish-forward: " + get_eml_subject(MainFrame.eml_path)
    pyperclip.copy(result)
    spam = pyperclip.paste()
    print(spam)
    pass

def copy_subject():
    result = get_eml_subject(MainFrame.eml_path)
    pyperclip.copy(result)
    spam = pyperclip.paste()
    print(spam)
    pass

def get_eml_subject(eml_path):

    eml_subject = ""
    if eml_path == "":
        return eml_subject

    with open(eml_path, 'rb') as eml_file:
        # Parse the EML file using the email library
        msg = email.message_from_bytes(eml_file.read())

        # Get the subject line from the message headers
        eml_subject = msg['Subject']

        # Print the subject line
        print('Subject:', eml_subject)
    if eml_subject == "":
        eml_subject = "FW:"

    return eml_subject


def get_urls():

    cleaned_urls = [""]

    if MainFrame.eml_path != '':
        with open(MainFrame.eml_path, 'rb') as eml_file:
            msg = email.message_from_bytes(eml_file.read())
            if msg.is_multipart():
            # If the message is multipart, iterate over the parts to find the plain text body
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
            else:
                # If the message is not multipart, the message body is in the main message
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

            print(body)

            url_regex = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
        
            url_list = re.findall(url_regex, body)
            url_list = [re.sub(r'[>\]]$', '', url) for url in url_list]
            url_list=list(set(url_list))
    
            cleaned_urls = [""]
            print(url_list)

            for url in url_list:
                if url.find("url=") != -1:
                    url = url[url.find("url=")+4:url.find("&data",url.find("url="))]
                    url = unquote(url)
                if url not in cleaned_urls:
                    cleaned_urls.append(url)
    
    cleaned_urls.pop(0)
    #MainFrame.__init__(MainFrame.__init__.self, title="Phish Curry")
    return cleaned_urls



def get_response(url):
    
    response = scan_url(url)
    redir_link_result = None
    last_analysis_stats = response[response.find("\'last_analysis_stats\':")+24:response.find("},",response.find("last_analysis_stats"))]
    link_results = last_analysis_stats
    redir_link_result = "N/A"
    print(last_analysis_stats)

    if response.find("\'last_final_url\':") != -1:
        last_final_url = response[response.find("\'last_final_url\':")+19:response.find("\',",response.find("last_final_url"))]
        if last_final_url != url:
            url = last_final_url
            response = scan_url(url)
            print("Scanning final url...." + url)
            last_analysis_stats = response[response.find("\'last_analysis_stats\':")+24:response.find("},",response.find("last_analysis_stats"))]
            #print(last_analysis_stats)
            redir_link_result = last_analysis_stats
        else:
            redir_link_result = "N/A"

    return link_results, redir_link_result

def copy_link(url):
    pyperclip.copy(str(url))
    spam = pyperclip.paste()


def scan_url(url):

    analysis_key = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url= "https://www.virustotal.com/api/v3/urls/" + analysis_key
    headers = {
    "accept": "application/json",
    "x-apikey": f"{vt_api_key}"
    }
    response = requests.get(vt_url, headers=headers)
    response = str(response.json())

    return response


class MainFrame(wx.Frame):
    
    eml_path = ""
    
    def __init__(self, title):
        super().__init__(parent=None, title=title, size=(800, 600))
        self.panel = wx.ScrolledWindow(self, style=wx.VSCROLL)

        self.panel.SetBackgroundColour((10, 10, 10))
        self.panel.SetForegroundColour((255, 255, 255))
        
        # Create top sizer for email subject
        top_sizer = wx.BoxSizer(wx.VERTICAL)
        subject_label = wx.StaticText(self.panel, label='Subject:' + get_eml_subject(MainFrame.eml_path))
        subject_label.SetFont(wx.Font(wx.FontInfo(12).Bold()))
        subject_label.SetForegroundColour((200, 200, 200)) # light grey
        top_sizer.Add(subject_label, 0, wx.ALL, 5)

        browse_button = wx.Button(self.panel, label='Browse', size=(120, -1))
        browse_button.SetFont(wx.Font(wx.FontInfo(12)))
        browse_button.SetForegroundColour((200, 200, 200)) # light grey
        browse_button.SetBackgroundColour((30, 30, 30)) # dark grey
        browse_button.Bind(wx.EVT_BUTTON, lambda event: self.define_path()) 
        top_sizer.Add(browse_button, 0, wx.ALL, 5)

        subject_button = wx.Button(self.panel, label='Copy Subject', size=(150, -1))
        subject_button.SetFont(wx.Font(wx.FontInfo(12)))
        subject_button.SetForegroundColour((200, 200, 200)) # light grey
        subject_button.SetBackgroundColour((30, 30, 30)) # dark grey
        subject_button.Bind(wx.EVT_BUTTON, lambda event: copy_subject()) #does the work
        top_sizer.Add(subject_button, 0, wx.ALL, 5)

        phishfwd_button = wx.Button(self.panel, label='Copy phish-fwd', size=(150, -1))
        phishfwd_button.SetFont(wx.Font(wx.FontInfo(12)))
        phishfwd_button.SetForegroundColour((200, 200, 200)) # light grey
        phishfwd_button.SetBackgroundColour((30, 30, 30)) # dark grey
        phishfwd_button.Bind(wx.EVT_BUTTON, lambda event: phish_fwd_cp()) #does the work
        top_sizer.Add(phishfwd_button, 0, wx.ALL, 5)


        self.panel.SetSizer(top_sizer)

        # Create sizer for URL/Attachment scanning results
        url_sizer = wx.BoxSizer(wx.VERTICAL)

        urls = get_urls()
        attachments = [] #change later

        for url in urls + attachments:
            url_panel = wx.Panel(self.panel)
            url_sizer.Add(url_panel, 0, wx.EXTEND_LAST_ON_EACH_LINE | wx.ALL, 0)

            # Add column for URL/Attachment name
            url_label = wx.TextCtrl(url_panel, value=url, style=wx.TE_READONLY, size=(400, -1))
            url_label.SetFont(wx.Font(wx.FontInfo(9)))
            url_panel_sizer = wx.BoxSizer(wx.HORIZONTAL)
            url_panel_sizer.Add(url_label, 0, wx.ALIGN_LEFT | wx.ALL, 5)

            # Add column for "Rescan" button
            scan_button = wx.Button(url_panel, label='Rescan', size=(80, -1))
            scan_button.SetFont(wx.Font(wx.FontInfo(9)))
            scan_button.Bind(wx.EVT_BUTTON, lambda event: get_response(url)) #does the work
            url_panel_sizer.Add(scan_button, 0, wx.ALIGN_LEFT | wx.ALL, 5)

            # Add column for "copy-link" button
            copy_button = wx.Button(url_panel, label='Copy-link', size=(80, -1))
            copy_button.SetFont(wx.Font(wx.FontInfo(9)))
            copy_button.Bind(wx.EVT_BUTTON, lambda event, url=url: copy_link(event.GetEventObject().GetParent().GetChildren()[0].GetValue())) #does the work
            url_panel_sizer.Add(copy_button, 0, wx.ALIGN_LEFT | wx.ALL, 5)

            link_results, redir_link_result = get_response(url)

            # Add column for scanning results
            result_textctrl = wx.TextCtrl(url_panel, value=link_results, style=wx.TE_READONLY, size=(400, -1))
            result_textctrl.SetFont(wx.Font(wx.FontInfo(9)))
            url_panel_sizer.Add(result_textctrl, 0, wx.ALIGN_LEFT | wx.ALL, 5)

            # Add column for additional comments
            comment_textctrl = wx.TextCtrl(url_panel, value=redir_link_result, size=(400, -1))
            comment_textctrl.SetFont(wx.Font(wx.FontInfo(9)))
            url_panel_sizer.Add(comment_textctrl, 0, wx.ALIGN_LEFT | wx.ALL, 5)

            url_panel.SetSizer(url_panel_sizer)

        
        top_sizer.Add(url_sizer, 1, wx.EXPAND | wx.ALL, 5)

        self.panel.SetSizer(top_sizer)
        self.panel.SetScrollRate(0, 10)

        self.Centre()
        self.Show()
    
    def define_path(self):
        frame = wx.Frame(None, -1, 'win.py')
        frame.SetDimensions(0,0,200,50)

        openFileDialog = wx.FileDialog(frame, "Open email file", wildcard="Email files (*.eml)|*.eml",
                       style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)
            
        openFileDialog.ShowModal() == wx.ID_CANCEL
        #        return     # the user changed their mind
            # Proceed loading the file chosen by the user
        pathname = openFileDialog.GetPath()
        print(f'Selected file: {pathname}')
        MainFrame.eml_path = pathname
        #MainFrame.__init__.Destroy()
        MainFrame.__init__(self, title="Phish-sticks")


def main():
    app = wx.App()
    Window = MainFrame("Phish-sticks")
    app.MainLoop()



if __name__ == '__main__':    
    main()

