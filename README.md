# AUTOSCAN with VirusTotal API

This script automatically scans the files where the script is running through the virustotal api!

# Setup 
Install the requirements, also you need go here: https://developers.virustotal.com/reference#getting-started and get your token. You have to put that token in the config.py file

# Observation
It cannot analyze files that are many megabytes due to API limitations, 
in theory there is a way to increase the upload size but I have not gotten to it yet.
