import wx
import re
import glob
from urllib.parse import unquote
import pyperclip
from email.parser import BytesParser
from email import policy
import vt
import requests
import base64

vt_api_key = 'VT_API_KEY'
client = vt.Client(vt_api_key)


def get_email_content():

    text=""
    print(MainFrame.eml_path)

    eml_files = glob.glob(MainFrame.eml_path) # get all .eml files in a list
    for eml_file in eml_files:
        with open(eml_file, 'rb') as fp:  # select a specific email file from the list
            name = fp.name # Get file name
            msg = BytesParser(policy=policy.default).parse(fp)
        #text = msg.get_body(preferencelist=('plain')).get_content()
        text = msg.get_body(preferencelist=('related', 'html', 'plain')).get_content()
        fp.close()
        text = text.split("\n")
    #print (name) # Get name of eml file
    #print (text) # Get list of all text in email
    email_contents = str(text)

    #email_contents = ""

    return email_contents


def phish_fwd_cp():
    result = "Phish-forward: FW:" + get_eml_subject()
    pyperclip.copy(result)
    spam = pyperclip.paste()
    print(spam)
    pass

def get_eml_subject():

    text = get_email_content()
    text = str(text)
    if (text.find("Subject:")) != -1:
        eml_subject = text[text.find("Subject:")+8:text.find(", \'",text.find("Subject:"))-1]
    else:
        eml_subject = ""

    return eml_subject


def get_urls():
    url_list = [""]
    link_list = re.findall(r'(https?://\S+)', str(get_email_content()))
    
    for url in link_list:
        start_pointer = -1
        end_pointer = -1
        if (max([url.find('<'),url.find('[')]) != -1):
            start_pointer = max([url.find('<'),url.find('[')])
        if (max([url.find('>'),url.find(']')]) != -1):
            end_pointer = max([url.find('>'),url.find(']')])
        
        char_list = ['\'', '"', '\r', ',', ';', ')', '(', '}', '{']
        for char in char_list:
            url = url.replace(char,'')
        if end_pointer == -1:
            url = url[start_pointer+1:end_pointer] + url[end_pointer]
        else:
            url = url[start_pointer+1:end_pointer]
        url_list.append(url)
    url_list.pop(0)

    cleaned_urls = [""]

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
    "x-apikey": "VT_API_KEY"
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
        subject_label = wx.StaticText(self.panel, label='Subject:' + get_eml_subject())
        subject_label.SetFont(wx.Font(wx.FontInfo(12).Bold()))
        subject_label.SetForegroundColour((200, 200, 200)) # light grey
        top_sizer.Add(subject_label, 0, wx.ALL, 5)

        browse_button = wx.Button(self.panel, label='Browse', size=(120, -1))
        browse_button.SetFont(wx.Font(wx.FontInfo(12)))
        browse_button.SetForegroundColour((200, 200, 200)) # light grey
        browse_button.SetBackgroundColour((30, 30, 30)) # dark grey
        browse_button.Bind(wx.EVT_BUTTON, lambda event: self.define_path()) 
        top_sizer.Add(browse_button, 0, wx.ALL, 5)

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

