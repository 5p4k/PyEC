from modules.safecomm import ECDHClient, ECDHServer
from modules.netcomm import runConnectOrListen
import sys

import modules.logging

if 'silent' in sys.argv:
	modules.logging.LOG_LEVEL=modules.logging.LOG_ERROR | modules.logging.LOG_INCOMING | modules.logging.LOG_IMPORTANTINFO

if __name__ == "__main__":
    channel=runConnectOrListen(clientClass=ECDHClient, serverClass=ECDHServer)
    input=raw_input()
    while len(input)>0:
        channel.sendEncryptedMessage(input)
        input=raw_input()

    channel.stopListening()