#!/usr/bin/env python
#
# A simple  application
#
# (C) 2021-2022 Juan Antonio Arizaga  <arizaga@gmail.com>
#
# contador

from collections import defaultdict
import pyshark
from statistics import mean, pstdev, variance


def funcion(info: list,indice: list) -> None:
    """Funcion que obtiene los parametros medibles de cada trama (frame)
    dentro de un flujo en un archivo CAP
# 0 es el numero de frames
# 1 es la cantidad de bytes que llegan, aun no dividido entre fordward y backward
# 2 es el periodo de tiempo entre frames
# 3 es el tiempo del primer frame, para saber el tiempo total u otro dato
# 4 es el tiempo del ultimo frame visitado, para poder sacar el dato anterior
# 5 es el ip de la promera fuente
# 6 es el puerto de la fuente
# 7 es el ip del primer destino
# 8 es el puerto de destino
# 9 es el tipo de protocolo utilizado
#10 es la cantidad de bytes forward
#11 es la cantidad de frames forward
#12 es la cantidad de bytes backward
#13 es la cantidad de frames backward
#14 es la lista de bytes forward
#15 es la lista de bytes backward
#16 es la media de bytes forward
#17 es la media de bytes backward
#18 es la std de bytes forward
#19 es la std de bytes backward
#20 es la lista del periodo de tiempo entre frames fwd
#21 es la lista del periodo de tiempo entre frames bck
#22 es la velocidad de tx forward
#23 es la velocidad de tx backward
***  nuevo espero jale
#24 es el hopcount del layer AODV
#25 es el dest_seq del layer AODV
#26 es la media del hopcount del layer AODV
#27 es el std del hopcount del layer AODV
#28 es la media del dest_seq del layer AODV
#29 es el std del dest_seq del layer AODV
#30 es el nombre del frame
"""

    frammes=info[0]
    # pero llamo al numero de frame que debe existir, si no existe creamos el frame
    frammes+=1       #si sí existe incrementamos el frame
    #print(info[2],info[3],info[4])

    bites=info[1]   #numero de bytes en el frame incrementa el numero de bytes totales
    bites+=int(indice.length)
    periodo=info[2]#se va guardando el tiempo entre este frame y el anterior

    ahora=indice.sniff_time.timestamp()
    antes=info[4]
    delta= ahora-antes
    info[0]=frammes
    info[1]=bites
    if delta>=0:        #frames no repetidos
        #info[0]=frammes
        #periodo= periodo+delta
        info[2].append(delta)
        info[4]=ahora
        #info[1]=bites
    try:
        src_addr = indice.ip.src
    except AttributeError:

        src_addr = indice.ipv6.src

    if info[5]==src_addr:   #forward
        info[10]+=int(indice.length)
        ff=info[11]
        ff+=1
        info[11]=ff
        info[14].append(int(indice.length))
        info[16]=mean(info[14])
        info[18]=pstdev(info[14])
        info[20].append(ahora)


    if info[7]==src_addr:   #backward
        info[12]+=int(indice.length)
        ff=info[13]
        ff+=1
        info[13]=ff
        info[15].append(int(indice.length))
        info[17]=mean(info[15])
        info[19]=pstdev(info[15])
        info[21].append(ahora)
    if sum(info[2])!= 0 :
        info[22]= round(8*(info[10])/sum(info[2]))
        info[23]= round(8*(info[12])/sum(info[2]))
    else:
        info[22]= 0
        info[23]= 0
#Nuevo 18 de mayo
    if indice.layers[4].get('hopcount') is None:
        info[24].append(-1)
        info[25].append(-1)
        # info[26]=0
        # info[27]=0
        # info[28]=0
        # info[29]=0
    else:
        info[24].append(int(indice.layers[4].get('hopcount')))
        info[25].append(int(indice.layers[4].get('aodv.dest_seqno')))
        info[26]=mean(info[24])
        info[27]=pstdev(info[24])
        info[28]=mean(info[25])
        info[29]=pstdev(info[25])

    return None


def funcion_agregar(i : int,Directorio : dict, indice: list) -> None:
    """Función que agrega el primer frame de un flujo dentro del archivo PCAP

    Parametros
    i : int
    número de frame que se desea agregar

    indice: list
    es la información del frame que se tomo del archivo PCAP

    Directorio: dict
    Es el destino de la información que estamos manejando

    """
    Directorio.setdefault(i)
    protocol =  indice.transport_layer
    try:
        src_addr = indice.ip.src
    except AttributeError:
        #print(indice)
        src_addr = indice.ipv6.src
    src_port = indice[indice.transport_layer].srcport
    try:
        dst_addr = indice.ip.dst
    except AttributeError:
        #print(indice)
        dst_addr = indice.ipv6.dst
    dst_port = indice[indice.transport_layer].dstport
    lista=(
    [1,                             #00
        int(indice.length) ,          #01
        [0],                            #02
        indice.sniff_time.timestamp(),#03
        indice.sniff_time.timestamp(),#04
        src_addr,                    #05
        src_port,                   #06
        dst_addr,                   #07
        dst_port,                   #08
            protocol,                  #09
            int(indice.length),       #10
            1,                         #11
            0,                         #12
            0,                          #13
            [int(indice.length)],       #14
            [],                          #15
            0,                          #16
            0,                          #17
            0,                          #18
            0,                          #19
            [0],                          #20
            [0],                          #21
            0,                          #22
            0,                          #23
            [],                          #24
            [],                          #25
            0,                          #26
            0,                          #27
            0,                          #28
            0,                          #29
            str(src_addr)+"_"+str(src_port)+"_"+str(dst_addr)+"_"+str(dst_port)])                       #30
    Directorio[i]=lista
    return None



def funcion_obtener(archivo: str):
    cap = pyshark.FileCapture(archivo)
    #cap = pyshark.FileCapture(r'C:\Users\j_ari\Downloads\pcap\Thursday-WorkingHours.pcap')
    Flujos_tcp_Dict = defaultdict(list)
    Flujos_udp_Dict = defaultdict(list)
    Flujos_Dict = defaultdict(list)
from collections import defaultdict
import pyshark
from statistics import mean, pstdev, variance

# Esta función obtiene los parámetros medibles de cada trama (frame)
# dentro de un flujo en un archivo CAP
def funcion(info: list, indice: list) -> None:
    """
    # 0 es el número de frames
    # 1 es la cantidad de bytes que llegan, aún no dividido entre forward y backward
    # 2 es el periodo de tiempo entre frames
    # 3 es el tiempo del primer frame, para saber el tiempo total u otro dato
    # 4 es el tiempo del último frame visitado, para poder sacar el dato anterior
    # 5 es el IP de la primera fuente
    # 6 es el puerto de la fuente
    # 7 es el IP del primer destino
    # 8 es el puerto de destino
    # 9 es el tipo de protocolo utilizado
    # 10 es la cantidad de bytes forward
    # 11 es la cantidad de frames forward
    # 12 es la cantidad de bytes backward
    # 13 es la cantidad de frames backward
    # 14 es la lista de bytes forward
    # 15 es la lista de bytes backward
    # 16 es la media de bytes forward
    # 17 es la media de bytes backward
    # 18 es la desviación estándar de bytes forward
    # 19 es la desviación estándar de bytes backward
    # 20 es la lista del periodo de tiempo entre frames fwd
    # 21 es la lista del periodo de tiempo entre frames bck
    # 22 es la velocidad de tx forward
    # 23 es la velocidad de tx backward
    # 24 es el hopcount del layer AODV
    # 25 es el dest_seq del layer AODV
    # 26 es la media del hopcount del layer AODV
    # 27 es la desviación estándar del hopcount del layer AODV
    # 28 es la media del dest_seq del layer AODV
    # 29 es la desviación estándar del dest_seq del layer AODV
    # 30 es el nombre del frame
    """

    h=0
    i=0; #numero de flujo
    j =0 #numero de indices
    k=0 #tramas retransmitidas
    for indice in cap:
        #
        # if indice.transport_layer  == 'TCP':
        #     i=int(indice.tcp.stream)
        # if indice.transport_layer  == 'UDP':
        #     i= int(indice.udp.stream)


        if indice.transport_layer == 'TCP':
            i=int(indice.tcp.stream)
            # try:
            #     print('Analisis flag:',indice.tcp.analysis_retransmission)
            #     k+=1
            # except AttributeError:
            try:
                info=Flujos_tcp_Dict[i]      #No sé si existe en el diccionario
                frammes=info[0]
                funcion(info,indice)
            except IndexError :
                funcion_agregar(i,Flujos_tcp_Dict,indice)
                j+=1  #numero de flujos contados

        if indice.transport_layer == 'UDP':
            i= int(indice.udp.stream)
            j+=1
            # try:
            #     print('Analisis flag:',indice.udp.analysis_retransmission)
            #except AttributeError:
            try:
                info=Flujos_udp_Dict[i]      #No sé si existe en el diccionario
                frammes=info[0]
                funcion(info,indice)
            except IndexError :
                funcion_agregar(i,Flujos_udp_Dict,indice)
                j+=1  #numero de flujos contados

    return Flujos_tcp_Dict,Flujos_udp_Dict,i,j,k
