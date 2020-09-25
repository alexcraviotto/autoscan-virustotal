# AUTOSCAN with VirusTotal API

This script automatically scans the files where the script is running through the virustotal api

# Setup 
To run this script you need Python and win10toast library. Also you need go here: https://developers.virustotal.com/reference#getting-started and get your token. Later make a file in the same folder as it named config.py, and write in it: token = "putyourtokenhere" 

# Observation
It cannot analyze files that are many megabytes due to API limitations, 
in theory there is a way to increase the upload size but I have not gotten to it yet.
