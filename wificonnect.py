import subprocess


def connectOpen(SSID, APMAC, interface):
	"""iwconfig wlan0 key 'mykey' mode managed essid 'mychannel' channel integer ap 00:00:00:00:00:00"""
	subprocess.check_output(["iwconfig", interface, "mode", "managed", "essid", "'"+SSID+"'", "channel", channel, "ap", APMAC])
