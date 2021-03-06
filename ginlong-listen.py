#!/usr/bin/env python
#===============================================================================
# Copyright (C) 2017 Darren Poulson
#
# This file is part of ginlong-mqtt.
#
# R2_Control is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# R2_Control is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ginlong-mqtt.  If not, see <http://www.gnu.org/licenses/>.
#===============================================================================

import paho.mqtt.publish as publish
import socket
import array
import binascii
import time
import sys
import string
import struct
import configparser
import io

config = configparser.RawConfigParser(allow_no_value=True)
with open("config.ini") as f:
    config.read_file(f)

###########################
# Variables

DEBUG = True
WRITE_LOG = False

encoding = 'utf-8'

listen_address = config.get('DEFAULT', 'listen_address')     # What address to listen to (0.0.0.0 means it will listen on all addresses)
listen_port = int(config.get('DEFAULT', 'listen_port'))      # Port to listen on

client_id = config.get('MQTT', 'client_id')                  # MQTT Client ID
client_pw = config.get('MQTT', 'client_pw')                  # MQTT Client Password
mqtt_auth = {'username':client_id, 'password':client_pw}

mqtt_server = config.get('MQTT', 'mqtt_server')              # MQTT Address
mqtt_port = int(config.get('MQTT', 'mqtt_port'))             # MQTT Port

############################
# Functions

def swaphex(hexdata):
    hexarray = array.array('h', hexdata)
    hexarray.byteswap()
    return hexarray.tobytes()[::-1]

def genhextime():
    # 5E8217A5 = Decimal 1585584037 = Monday, 30. March 2020 16:00:37
    secondsSinceEpoch = time.time()
    return binascii.hexlify(struct.pack('<I', round(secondsSinceEpoch)))

def createV5Response(dlserial, responsetype):
    headCode = binascii.unhexlify('a5') # headCode for V5 response
    unk1 = binascii.unhexlify('0a')
    unk2 = binascii.unhexlify('0010')
    if (responsetype == '0001'):
        unk3 = binascii.unhexlify('17e66b')
    elif (responsetype == '0101'):
        unk3 = binascii.unhexlify('120302')
    elif (responsetype == '0201'):
        unk3 = binascii.unhexlify('110201')
    elif (responsetype == '8101'):
        unk3 = binascii.unhexlify('130908')
    else:
        unk3 = binascii.unhexlify('000000')
    serial = binascii.unhexlify(dlserial)
    command = binascii.unhexlify(responsetype)
    hextime = binascii.unhexlify(genhextime())
    unk5 = binascii.unhexlify('78000000')
    # chksum
    endCode = binascii.unhexlify('15')

    chksrc = bytearray(headCode + unk1 + unk2 + unk3 + serial + command + hextime + unk5)
    chksum = 0
    chksrc_bytes = bytearray(chksrc)
    for i in range(1, len(chksrc_bytes) - 2, 1):
        chksum += chksrc_bytes[i] & 255
    chksum = int((chksum & 255))
    
    return binascii.hexlify(headCode + unk1 + unk2 + unk3 + serial + command + hextime + unk5 + chksum.to_bytes(1, 'big') + endCode)

############################

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((listen_address, listen_port))
sock.listen(1)
#sock.setblocking(0)
print('listening on %s:%s' % (listen_address, listen_port))

while True: 
    # Wait for a connection
    if DEBUG:
        print('waiting for a connection')
    sock.settimeout(None)
    conn,addr = sock.accept()
    conn.settimeout(60.0)

    try:
        if DEBUG:
            print('connection from', addr)
            rawdata = conn.recv(1024)                                 # Read in a chunk of data
            hexdata = binascii.hexlify(rawdata)                       # Convert to hex for easier processing
            if DEBUG:
                print('Length of hex data is %d' % len(hexdata))
                print('Hex data: %s' % hexdata)

            # Data logger serial message
            if (len(hexdata) == 28):
                print('Got data logger serial message')
                dlserial = int(swaphex(hexdata[14:22]), 16)
                if DEBUG:
                    print("Data logger serial: %s" % dlserial)

                # Send response
                response = createV5Response(str(hexdata[14:22], encoding), '0001')
                if DEBUG:
                    print('Response: %s' % response)
                rawdata = binascii.unhexlify(response)
                conn.sendall(rawdata)
                continue

            # Data logger access point message
            elif (len(hexdata) == 120):
                print('Got data logger access point message')
                dlserial = int(swaphex(hexdata[14:22]), 16)
                if DEBUG:
                    print("Data logger serial: %s" % dlserial)

                ##### Access point
                ap = str(binascii.unhexlify(str(hexdata[52:112], encoding)), encoding)
                if DEBUG:
                    print("Access point: %s" % ap)

                # Send response
                response = createV5Response(str(hexdata[14:22], encoding), '8101')
                if DEBUG:
                    print('Response: %s' % response)
                rawdata = binascii.unhexlify(response)
                conn.sendall(rawdata)
                continue

            # Data logger core data message
            elif (len(hexdata) == 198):
                print('Got data logger core data message')
                dlserial = int(swaphex(hexdata[14:22]), 16)
                if DEBUG:
                    print("Data logger serial %s" % dlserial)

                dlfirmware = str(binascii.unhexlify(str(hexdata[60:90], encoding)), encoding)
                if DEBUG:
                    print("Data logger firmware: %s" % dlfirmware)

                dlmac = str(hexdata[140:152], encoding)
                if DEBUG:
                    print("Data logger MAC: %s" % dlmac)

                # Send response
                response = createV5Response(str(hexdata[14:22], encoding), '0201')
                if DEBUG:
                    print('Response: %s' % response)
                rawdata = binascii.unhexlify(response)
                conn.sendall(rawdata)
                continue

            # Inverter payload from data logger
            elif (len(hexdata) == 476 or len(hexdata) == 492):
                print('Got inverter payload message')
                timestamp = (time.strftime("%F %H:%M"))     # get date time
                msgs = []

                ##### Data logger serial
                dlserial = int(swaphex(hexdata[14:22]), 16)
                if DEBUG:
                    print("Data logger serial: %s" % dlserial)

                ##### Inverter serial
                serial = str(binascii.unhexlify(str(hexdata[64:94], encoding)), encoding)
                if DEBUG:
                    print("Inverter serial: %s" % serial)

                ##### MQTT topic
                mqtt_topic = ''.join([client_id, "/", serial, "/"])   # Create the topic base using the client_id and serial number
                if DEBUG:
                    print('MQTT Topic:', mqtt_topic)

                          
                                                      
                         
                                        

                               
                                
                     
                               

                ##### Unknown
                unk = float(int(hexdata[94:96],16))
                if DEBUG:
                    print('Unknown:', unk)

                ##### Temperature
                temp = float(int(hexdata[96:98],16))
                if DEBUG:
                    print('Temp:', temp)

                ##### Temperature factor
                tempf = float(int(hexdata[98:100],16))
                if DEBUG:
                    print('Temp factor:', tempf)

                ##### Calculated temperature
                temp = (temp - 256 + (256 * tempf)) / 10
                if DEBUG:
                    print('Calculated Temp:', temp)
                msgs.append((mqtt_topic + "Temp", temp, 0, False))

                ##### Unknown
                unk = float(int(hexdata[100:102],16))
                if DEBUG:
                    print('Unknown:', unk)

                ##### Vpv1
                vpv1 = float(int(hexdata[102:106],16)) / 10
                if DEBUG:
                    print('Vpv1:', vpv1)
                msgs.append((mqtt_topic + "Vpv1", vpv1, 0, False))

                ##### Ipv1
                ipv1 = float(int(hexdata[106:110],16)) / 10
                if DEBUG:
                    print('Ipv1:', ipv1)
                msgs.append((mqtt_topic + "Ipv1", ipv1, 0, False))

                ##### Unknown
                unk = float(int(hexdata[110:114],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Vpv2
                vpv2 = float(int(hexdata[114:118],16)) / 10
                if DEBUG:
                    print('Vpv2:', vpv2)
                msgs.append((mqtt_topic + "Vpv2", vpv2, 0, False))
                
                ##### Ipv2
                ipv2 = float(int(hexdata[118:122],16)) / 10
                if DEBUG:
                    print('Ipv2:', ipv2)
                msgs.append((mqtt_topic + "Ipv2", ipv2, 0, False))

                ##### Iac1
                iac1 = float(int(hexdata[122:126],16)) / 10
                if DEBUG:
                    print('Iac1:', iac1)
                msgs.append((mqtt_topic + "Iac1", iac1, 0, False))

                ##### Iac2
                iac2 = float(int(hexdata[126:130],16)) / 10
                if DEBUG:
                    print('Iac2:', iac2)
                msgs.append((mqtt_topic + "Iac2", iac2, 0, False))

                ##### Iac3
                iac3 = float(int(hexdata[130:134],16)) / 10
                if DEBUG:
                    print('Iac2:', iac3)
                msgs.append((mqtt_topic + "Iac3", iac3, 0, False))

                ##### Unknown
                unk = float(int(hexdata[134:138],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Vac
                vac = float(int(hexdata[138:142],16)) / 10
                if DEBUG:
                    print('Vac:', vac)
                msgs.append((mqtt_topic + "Vac", vac, 0, False))

                ##### Unknown
                unk = float(int(hexdata[142:144],16))
                if DEBUG:
                    print('Unknown:', unk)
                         

                ##### Pac
                pac = float(int(hexdata[144:146],16))
                if DEBUG:
                    print('Pac:', pac)

                ##### Pacbase
                pacbase = float(int(hexdata[146:150],16))
                if DEBUG:
                    print('Pacbase:', pacbase)

                ##### Calculated Pac
                pac = pac + pacbase
                if DEBUG:
                    print('Calculated Pac:', pac)
                msgs.append((mqtt_topic + "Pac", pac, 0, False))

                ##### kWh today
                kwhtoday = float(int(hexdata[150:154],16)) / 100
                if DEBUG:
                    print('kwh today:', kwhtoday)

                ##### kWh today base
                kwhdbase = float(int(hexdata[154:158],16)) / 100
                if DEBUG:
                    print('kwh today base:', kwhdbase)

                ##### Calculated kWh today
                kwhtoday = (kwhdbase + kwhtoday)
                if DEBUG:
                    print('Calculated kwh today:', kwhtoday)
                msgs.append((mqtt_topic + "kwhtoday", kwhtoday, 0, False))

                ##### kWh total
                kwhtotal = float(int(hexdata[158:162],16)) / 10
                if DEBUG:
                    print('kwh total:', kwhtotal)

                ##### kwh total base
                kwhabase = float(int(hexdata[162:166],16)) / 10
                if DEBUG:
                    print('kwh total base:', kwhabase)

                ##### Calculated kwh total
                kwhtotal = (kwhabase + kwhtotal)
                if DEBUG:
                    print('Calculated kwh total:', kwhtotal)
                msgs.append((mqtt_topic + "kwhtotal", kwhtotal, 0, False))

                ##### Unknown
                unk = float(int(hexdata[166:170],16))
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[170:174],16))
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[174:176],16))
                if DEBUG:
                    print('Unknown:', unk)

                ##### Operation mode
                opmode = float(int(hexdata[176:178],16))
                if DEBUG:
                    print('Opmode:', opmode)

                ##### Unknown
                unk = float(int(hexdata[178:182],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[182:186],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[186:190],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[190:194],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[194:198],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[198:202],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[202:206],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[206:210],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)
                         

                ##### Unknown
                unk = float(int(hexdata[210:214],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[214:218],16))
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown base
                unkbase = float(int(hexdata[218:222],16))
                if DEBUG:
                    print('Unknown base:', unkbase)

                ##### Calculated unknown
                unk = unkbase + unk
                if DEBUG:
                    print('Calculated unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[222:226],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[226:230],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Unknown
                unk = float(int(hexdata[230:234],16)) / 10
                if DEBUG:
                    print('Unknown:', unk)

                ##### Ppv
                ppv = float(int(hexdata[232:234],16))
                if DEBUG:
                    print('Ppv:', ppv)

                ##### Ppvbase
                ppvbase = float(int(hexdata[234:236],16))
                if DEBUG:
                    print('Ppvbase:', ppvbase)

                ##### Calculated Ppv
                ppv = (ppvbase * 256) + ppv
                if DEBUG:
                    print('Calculated Ppv:', ppv) 
                msgs.append((mqtt_topic + "Ppv1", ppv, 0, False))

                ##### Inverter Model
                inverter_model = str(swaphex(hexdata[316:320]), encoding)
                if DEBUG:
                    print('Inverter model:', inverter_model)
            
                ##### Firmware version main
                firmware_version_main = str(swaphex(hexdata[320:324]), encoding)
                if DEBUG:
                    print('Firmware version (main):', firmware_version_main)

                ##### Firmware version slave
                firmware_version_slave = str(swaphex(hexdata[324:328]), encoding)
                if DEBUG:
                    print('Firmware version (slave):', firmware_version_slave)

                publish.multiple(msgs, hostname=mqtt_server, auth=mqtt_auth)

                if WRITE_LOG:
                    file = open("rawlog",'a')
                    file.write(timestamp + ' ' + hexdata + '\n')
                    file.close()

                # Send response
                response = createV5Response(str(hexdata[14:22], encoding), '0101')
                if DEBUG:
                    print('Response: %s' % response)
                rawdata = binascii.unhexlify(response)
                conn.sendall(rawdata)

            else:
                print('hexdata has invalid length')

    except socket.timeout:
        print("Socket timeout occured!")
        # Send response
        response = createV5Response('4e4fa7ef', '1000')
        if DEBUG:
            print('Response: %s' % response)
        rawdata = binascii.unhexlify(response)
        conn.sendall(rawdata)
    except:
        print("Oops!", sys.exc_info()[0], "occured.")
    finally:
        if DEBUG:
            print("Finally")
        conn.shutdown(socket.SHUT_RDWR)
