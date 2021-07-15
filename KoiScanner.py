import tkinter as tk
import numpy as np
import pandas as pd

#function to check if the url is keyed in
def show_entry_fields():
    print(e2.get())

#def check()
    #not build yet

master = tk.Tk() #Init
#Stuff to be displayed and it's location
tk.Label(master,text="Please Paste The Link Here").grid(row=0)
tk.Label(master).grid(row=1)

#Entry Box and Its location
e2 = tk.Entry(master)
e2.grid(row=1, column=0)

#Buttons and its process
tk.Button(master,text='Quit',command=master.quit).grid(row=3,column=0,sticky=tk.W,pady=2)
tk.Button(master,text='Show', command=show_entry_fields).grid(row=3,column=1,sticky=tk.W,pady=2)

#Start the programme
tk.mainloop()