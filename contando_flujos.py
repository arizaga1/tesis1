#!/usr/bin/env python
# A simple PCAP extraction file
#
# (C) 2021-2022 Juan Antonio Arizaga  <arizaga@gmail.com>
#

import csv
import os
import tkinter as tk
from tkinter import filedialog
import pandas as pd
from contador import funcion, funcion_agregar, funcion_obtener


os.chdir(r'/home/mohamed/Escritorio/Ns3_modificado/ns-allinone-3.33/ns-3.33/mi_codigo_python/')

dd = 0

root = tk.Tk()
root.withdraw()
e = filedialog.askopenfilename()

while e != '':
    dd = 1
    Flujos_tcp_Dict, Flujos_udp_Dict, i, j, k = funcion_obtener(e)
    df = pd.DataFrame(Flujos_udp_Dict)

    if dd == 1:
        # Joining file name and extension using string slicing
        output_file_name = os.path.join(e[0:e.rfind("/")], 'test' + e[e.rfind("/") + 1:e.rfind("pcap") - 1] + '.csv')
        df.T.to_csv(output_file_name, index=False, header=True)
    else:
        df1 = pd.read_csv(e[0:e.rfind("/")]+"/test.csv")
        df1 = df1.join(df)
        df1.to_csv(e[0:e.rfind("/")]+"/test.csv", index=False, header=True)

    e = filedialog.askopenfilename()

os.system("clear")
print('Finalizado')
dd = 0
