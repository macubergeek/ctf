#!/usr/bin/python

import wx
from gnuradio import gr 
from gnuradio.wxgui import stdgui2, fftsink2, slider, form

import os
import time


class key_source_panel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)

	self.txt_len = 0

 	self.SetFont(wx.Font(15,wx.NORMAL, wx.NORMAL, wx.NORMAL))

        self.sizer2 = wx.BoxSizer(wx.HORIZONTAL)
        self.sizer3 = wx.BoxSizer(wx.HORIZONTAL)
        self.sizer4 = wx.BoxSizer(wx.HORIZONTAL)
        self.sizer5 = wx.BoxSizer(wx.HORIZONTAL)

        # Use some sizers to see layout options
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.sizer2, 0, wx.EXPAND)
        self.sizer.Add(self.sizer4, 0, wx.EXPAND)
        self.sizer.Add(self.sizer3, 0, wx.EXPAND)
        self.sizer.Add(self.sizer5, 0, wx.EXPAND)



	# buttons
        self.buttons = []
	self.buttons.append(wx.Button(self, -1, "Ctrl+Alt+Del"))
	self.buttons.append(wx.Button(self, -1, "Windows+r"))
	self.buttons.append(wx.Button(self, -1, "SYNC"))
	self.buttons.append(wx.Button(self, -1, "CR"))
	self.buttons.append(wx.Button(self, -1, "ESC"))
	self.buttons.append(wx.Button(self, -1, "Clear Text"))

	for i in range(3):  
		self.sizer2.Add(self.buttons[i], 1, wx.EXPAND)

	for i in range(3,6):  
		self.sizer4.Add(self.buttons[i], 1, wx.EXPAND)


	self.Bind(wx.EVT_BUTTON, self.OnButton1, self.buttons[0])
	self.Bind(wx.EVT_BUTTON, self.OnButton2, self.buttons[1])
	self.Bind(wx.EVT_BUTTON, self.OnButton3, self.buttons[2])
	self.Bind(wx.EVT_BUTTON, self.OnButton4, self.buttons[3])
	self.Bind(wx.EVT_BUTTON, self.OnButton5, self.buttons[4])
	self.Bind(wx.EVT_BUTTON, self.OnButton6, self.buttons[5])


        # the edit control - one line version.
        self.text = wx.TextCtrl(self)
        self.Bind(wx.EVT_TEXT, self.EvtText, self.text)
	self.sizer3.Add(self.text, 1, wx.EXPAND)


        self.lbl = wx.StaticText(self, label="\n2011 Faehnle, Hauff",)
	self.lbl.SetFont(wx.Font(10,wx.NORMAL, wx.NORMAL, wx.NORMAL))
	self.sizer5.Add(self.lbl, 1, wx.ALIGN_RIGHT)

        #Layout sizers
        self.SetSizer(self.sizer)
        self.SetAutoLayout(1)
        self.sizer.Fit(self)

	#focus txt
	self.text.SetFocus()
  
    def OnButton1(self,event):
        print "SENDING Ctrl+Alt+Del"
	self.write_char_to_file(chr(28)) #FS

    def OnButton2(self,event):
        print "SENDING Windows+r"
	self.write_char_to_file(chr(30)) #RS

    def OnButton3(self,event):
        print "SENDING SYNC"
	self.write_char_to_file(chr(26)) #sub

    def OnButton4(self,event):
        print "SENDING CR"
	self.write_char_to_file(chr(13)) #CR

    def OnButton5(self,event):
        print "SENDING ESC"
	self.write_char_to_file(chr(27)) #esc

    def OnButton6(self,event):
	self.text.SetValue("")
	self.txt_len = 0

    def EvtText(self, event):
        txt = event.GetString()
        if (self.txt_len >= len(event.GetString())): #deleted
	    if (len(event.GetString()) > 0 or self.txt_len==1):
		print "SENDING DEL"
		self.write_char_to_file(chr(31)) #remove
	else:
	    key = txt[len(txt)-1]
	    #print "pressed",key
	    self.write_char_to_file(key)

	self.txt_len = len(txt)

    def write_char_to_file(self,key):
	#write char to file
	if os.path.exists("/tmp/key_src.read_lock"):
		print "read_lock found, delaying"
		time.sleep(0.1)
	file2 = open('/tmp/key_src.lock', 'w')	
	file2.close() 	 
	file1 = open('/tmp/key_src.txt', 'a')	 
	file1.write(key)	 
	file1.close()
	os.remove('/tmp/key_src.lock')


def lkey_src_gui_run ():

	app = wx.App(False)
	frame = wx.Frame(None,size=(850,150),title="Keyboard Source GUI")
	panel = key_source_panel(frame)
	frame.Center()
	frame.Show()
	app.MainLoop()


if __name__ == '__main__':
	lkey_src_gui_run()




