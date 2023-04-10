# -*- coding: utf-8 -*-

# ▄▄▄▄    ▒█████   ▒█████                     ▄▄▄▄    █    ██  ██▀███   ██▓███   ▐██▌ 
#▓█████▄ ▒██▒  ██▒▒██▒  ██▒                  ▓█████▄  ██  ▓██▒▓██ ▒ ██▒▓██░  ██▒ ▐██▌ 
#▒██▒ ▄██▒██░  ██▒▒██░  ██▒                  ▒██▒ ▄██▓██  ▒██░▓██ ░▄█ ▒▓██░ ██▓▒ ▐██▌ 
#▒██░█▀  ▒██   ██░▒██   ██░                  ▒██░█▀  ▓▓█  ░██░▒██▀▀█▄  ▒██▄█▓▒ ▒ ▓██▒ 
#░▓█  ▀█▓░ ████▓▒░░ ████▓▒░ ██▓  ██▓  ██▓    ░▓█  ▀█▓▒▒█████▓ ░██▓ ▒██▒▒██▒ ░  ░ ▒▄▄  
#░▒▓███▀▒░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▓▒  ▒▓▒  ▒▓▒    ░▒▓███▀▒░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░▒▓▒░ ░  ░ ░▀▀▒ 
#▒░▒   ░   ░ ▒ ▒░   ░ ▒ ▒░  ░▒   ░▒   ░▒     ▒░▒   ░ ░░▒░ ░ ░   ░▒ ░ ▒░░▒ ░      ░  ░ 
# ░    ░ ░ ░ ░ ▒  ░ ░ ░ ▒   ░    ░    ░       ░    ░  ░░░ ░ ░   ░░   ░ ░░           ░ 
# ░          ░ ░      ░ ░    ░    ░    ░      ░         ░        ░               ░    
#      ░                     ░    ░    ░           ░                                  


#Its me!
__author__ = 'Rigel Forneris'

# Imports from burp
from burp import IBurpExtender #required for burp to burp
from burp import IContextMenuFactory  # right click functionality

# imports from python
import json
import codecs
from org.python.core import PyString
import re
import requests
import base64

# imports from java
from java.io import File, FileOutputStream
from java.lang import String
import jarray
from javax.swing import JMenuItem
from java.util import List, ArrayList
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing import JFrame
from javax.swing import JFileChooser

class BurpExtender(IBurpExtender,IContextMenuFactory,JFrame):
    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None
        self.hosts = set()

        #Define extension properties
        callbacks.setExtensionName("Boo Burp")
        callbacks.registerContextMenuFactory(self)

        #this is just providing a place where the save box can sit in, no need for it to be visible on start
        self.setVisible(False)
        return

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()        

        menu_list.add(JMenuItem("Just parse request!", actionPerformed=self.print_parser))
    
        menu_list.add(JMenuItem("Create standalone boofuzz .py", actionPerformed=self.filesave))

        menu_list.add(JMenuItem("Send to autofuzz!", actionPerformed=self.autofuzz))

        return menu_list 

    def print_parser(self,event):        
        print(self.parser(event))

    


    #Generate the traffic data from burp
    def traffic_data(self,event):
        http_traffic = self.context.getSelectedMessages()
        for traffic in http_traffic:            
            #Get request data
            
            http_request = traffic.getRequest()
            
            http_service = traffic.getHttpService()            
            
            request_info = self._helpers.analyzeRequest(http_service, http_request)
            
            #Get headers data
            global headers
            headers = request_info.getHeaders()

            #Get the HTTP method
            global method
            method = request_info.getMethod()
            
            global header_export
            header_export={}

            for header_line in headers:
                #create a new fresh regex!
                regex="(?P<static>("+method+"|.*:)) (?P<string>.*)"
                #Apply a regex to extract what will be static (what i will not fuzz) and string (what i will fuzz)
                header_parsed = re.search(regex, str(header_line))
                #Get regex captured groups
                static_part = header_parsed.group('static')
                string_part = header_parsed.group('string')
                #list_line="\""+static_part+"\": \""+string_part+"\""
                list_line={static_part : string_part}
                
                #print(type(list_line))
               
                header_export.update(list_line)
           
            header_export=base64.b64encode(str(header_export).encode('utf-8'))

            #Get the request URI
            global uri
            uri = request_info.getUrl().getPath()

            #Get the request URL
            
            url = request_info.getUrl().toString()
            # Use regex to extract the host name            
            host_regex = re.compile(r'http(s)?://([^:/]+)')
            match = host_regex.search(url)
            global host
            host = match.group(2)

            #get body data
            body_offset=request_info.getBodyOffset()
            '''
            body_bytes = http_request[body_offset:]
            body_list_bytes = body_bytes.split(b',')
            #body_list_str = [x.decode('utf-8') for x in body_bytes]
            #body_list_str = [x.replace('{', '').replace('}', '') for x in body_list_str]
            global body
            body = body_list_bytes
            '''
            global body_bytes
            body_bytes = http_request[body_offset:]   
            # Converte o objeto array em uma string
            try:
                global body_test           
                body_test = body_bytes.tostring().decode('utf-8')
                body_test=base64.b64encode(str(body_test).encode('utf-8'))

                body_str = codecs.decode(body_bytes.tostring(), 'utf-8')
                body_str = body_str.replace("{", "").replace("}", "")
                global body
                body = body_str.split(",")
            except:
                global body_test 
                body_test="{}"
                global body
                body="{}"
            

    def autofuzz(self,event):

        print("Function not available, yet!")

    #Parse the traffic
    def parser(self,event):
        self.traffic_data(event)

        content='''
#!/usr/bin/env python3
from boofuzz import *

def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("juiceshop.testzone", 80)),
    )

    s_initialize(name="Request")
    with s_block("Request-Line"):

            '''+ "\n"

        #add items to array, so i can compare all itens together
        item_verify=[]
        item_verify.append(method)
        item_verify.append(uri)
        item_verify.append(host)
        item_verify = "|".join(item_verify)

        #Returns header parsed!
        #print("Header parsed:")
        for header_line in headers:
            #create a new fresh regex!
            regex="(?P<static>("+method+"|.*:)) (?P<string>.*)"
            #Apply a regex to extract what will be static (what i will not fuzz) and string (what i will fuzz)
            header_parsed = re.search(regex, str(header_line))
            
            #Get regex captured groups
            static_part = header_parsed.group('static')
            string_part = header_parsed.group('string')
            
            #print the static item
            content +="        s_static(\'"+static_part+" \')" + "\n"

            #print("        s_static(\'"+static_part+" \')")
            
            #I dont want to fuzz the method, the URI and host values, so i will compare to exclude then.
            if re.search(item_verify, string_part):            
                content +="        s_static(\'"+string_part+" \')" + "\n"
            else:                
                content +="        s_string(\'"+string_part+"\')" + "\n"                

              
        try:
            content +='''  
    with s_block("Body-Content"):        
                ''' + "\n"  
            for body_line in body:
                body_regex="(?P<static>(.*:))(?P<string>.*)"
                body_parsed = re.search(body_regex, str(body_line))
                #print(body_line)

                body_static_part = body_parsed.group('static')
                body_string_part = body_parsed.group('string')

                content +="        s_static(\'"+body_static_part+"\')" + "\n"
                content +="        s_string(\'string_data\')" + "\n"
            
        except:
            content = content.replace('with s_block("Body-Content"):', '')
        content +='''
    session.connect(s_get("Request"))
    session.fuzz()

if __name__ == "__main__":
    main()
        '''
        return(content)


########################################################################################################################################################################################################################

    def filesave(self,event):
        
        # Create a new file chooser dialog
        file_chooser = JFileChooser()
        
        # Show the "Save as" dialog and get the result
        result = file_chooser.showSaveDialog(None)
        
        if result == JFileChooser.APPROVE_OPTION:
            # Get the selected file
            selected_file = file_chooser.getSelectedFile()                                    
            output_stream = FileOutputStream(selected_file.getAbsolutePath())
            
            content=self.parser(event)
            print(content)
            output_stream.write(content.encode("utf-8"))
            output_stream.close()
            
            # Print a message to the Extender console
            print("File saved to " + selected_file.getAbsolutePath())
        else:
            # User cancelled the "Save as" dialog
            print("User cancelled the Save as dialog.")
        
        return
        


        
