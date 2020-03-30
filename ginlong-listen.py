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
    secondsSinceEpoch = time.time()
    return binascii.hexlify(struct.pack('<I', round(secondsSinceEpoch)))

############################

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((listen_address, listen_port))
sock.listen(1)
print('listening on %s:%s' % (listen_address, listen_port))

while True: 
    # Wait for a connection
    if DEBUG:
        print('waiting for a connection')
    conn,addr = sock.accept()
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
                    print("Data logger serial %s" % dlserial)

                #### FIXME
                response = 'a50a001017e66b' + str(hexdata[14:22], encoding) + '0001' + str(genhextime(), encoding) + '780000002c15'
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
                    print("Data logger serial %s" % dlserial)

                ##### Access point
                serial = str(binascii.unhexlify(str(hexdata[52:112], encoding)), encoding)
                if DEBUG:
                    print("Access point: %s" % serial)

                #### FIXME
                response = 'a50a0010130908' + str(hexdata[14:22], encoding) + '8101' + str(genhextime(), encoding) + '78000000af15'
                if DEBUG:
                    print('Response: %s' % response)
                rawdata = binascii.unhexlify(response)
                conn.sendall(rawdata)
                continue

            # Data logger inverter  message
            elif (len(hexdata) == 198):
                print('Got inverter core data message')
                dlserial = int(swaphex(hexdata[14:22]), 16)
                if DEBUG:
                    print("Data logger serial %s" % dlserial)

                #### FIXME
                response = 'a50a0010110201' + str(hexdata[14:22], encoding) + '0201' + str(genhextime(), encoding) + '780000001715'
                if DEBUG:
                    print('Response: %s' % response)
                rawdata = binascii.unhexlify(response)
                
                conn.sendall(rawdata)
                continue

            # Inverter data from data logger
            elif (len(hexdata) == 492):
                print('Got inverter payload message')
                timestamp = (time.strftime("%F %H:%M"))     # get date time
                msgs = []

                ##### Data logger serial
                dlserial = int(swaphex(hexdata[14:22]), 16)
                if DEBUG:
                    print("Data logger serial %s" % dlserial)

                ##### Inverter serial
                serial = str(binascii.unhexlify(str(hexdata[64:94], encoding)), encoding)
                if DEBUG:
                    print("Inverter serial %s" % serial)

                ##### MQTT topic
                mqtt_topic = ''.join([client_id, "/", serial, "/"])   # Create the topic base using the client_id and serial number
                if DEBUG:
                    print('MQTT Topic:', mqtt_topic)

                ##### Temperature
                temp = float(int(hexdata[96:98],16))/10
                if DEBUG:
                    print('Temp: ', temp)
                msgs.append((mqtt_topic + "Temp", temp, 0, False))

                ##### Ppv1
                ppv1 = float(int(hexdata[98:102],16))
                if DEBUG:
                    print('Ppv1: ', ppv1)
                msgs.append((mqtt_topic + "Ppv1", ppv1, 0, False))

                ##### Vpv1
                vpv1 = float(int(hexdata[102:106],16))/10
                if DEBUG:
                    print('Vpv1: ', vpv1)
                msgs.append((mqtt_topic + "Vpv1", vpv1, 0, False))

                ##### Ipv1
                ipv1 = float(int(hexdata[106:110],16))/10
                if DEBUG:
                    print('Ipv1: ', ipv1)
                msgs.append((mqtt_topic + "Ipv1", ipv1, 0, False))

                ##### Ppv2
                ppv2 = float(int(hexdata[110:114],16))
                if DEBUG:
                    print('Ppv2: ', ppv2)
                msgs.append((mqtt_topic + "Ppv2", ppv2, 0, False))

                ##### Vpv2
                vpv2 = float(int(hexdata[114:118],16))/10
                if DEBUG:
                    print('Vpv2: ', vpv2)
                msgs.append((mqtt_topic + "Vpv2", vpv2, 0, False))
                
                ##### Ipv2
                ipv2 = float(int(hexdata[118:122],16))/10
                if DEBUG:
                    print('Ipv2: ', ipv2)
                msgs.append((mqtt_topic + "Ipv2", ipv2, 0, False))

                ##### Iac1
                iac1 = float(int(hexdata[122:126],16))/10
                if DEBUG:
                    print('Iac1: ', iac1)
                msgs.append((mqtt_topic + "Iac1", iac1, 0, False))

                ##### Iac2
                iac2 = float(int(hexdata[126:130],16))
                if DEBUG:
                    print('Iac2: ', iac2)
                msgs.append((mqtt_topic + "Iac2", iac2, 0, False))

                ##### Iac3
                iac3 = float(int(hexdata[130:134],16))
                if DEBUG:
                    print('Iac2: ', iac3)
                msgs.append((mqtt_topic + "Iac3", iac3, 0, False))

                ##### Unknown
                unk = float(int(hexdata[134:138],16))
                if DEBUG:
                    print('Unknown: ', unk)
                #msgs.append((mqtt_topic + "Unknown", unk, 0, False))

                ##### Vac
                vac = float(int(hexdata[138:142],16))/10
                if DEBUG:
                    print('Vac: ', vac)
                msgs.append((mqtt_topic + "Vac", vac, 0, False))

                ##### Fac
                fac = float(int(hexdata[142:146],16))/100
                if DEBUG:
                    print('Fac: ', fac)
                msgs.append((mqtt_topic + "Fac", fac, 0, False))

                ##### Unknown
                unk = float(int(hexdata[146:150],16))
                if DEBUG:
                    print('Unknown: ', unk)

                ##### kWh today
                kwhtoday = float(int(hexdata[150:154],16))/100
                if DEBUG:
                    print('kwh today: ', kwhtoday)
                msgs.append((mqtt_topic + "kwhtoday", kwhtoday, 0, False))

                ##### Unknown
                unk = float(int(hexdata[154:158],16))
                if DEBUG:
                    print('Unknown: ', unk)

                ##### kWh total
                kwhtotal = float(int(hexdata[158:162],16))/10
                if DEBUG:
                    print('kwh total: ', kwhtotal)
                msgs.append((mqtt_topic + "kwhtotal", kwhtotal, 0, False))

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
            else:
                print('hexdata has invalid length')

    finally:
        if DEBUG:
            print("Finally")
