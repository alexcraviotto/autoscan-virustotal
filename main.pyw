import requests
import os
import time
import win10toast
import config

class virustotal():
    def __init__(self):
        self.api = config.api

    def scan_file(self, file):
        url_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params_scan = {'apikey':self.api}
        try:
            file_scan = {'file': (file, open(file, 'rb'))}
            response_scan = requests.post(url_scan, files=file_scan, params=params_scan)
            time.sleep(5)
            data_scan = response_scan.json()
            resource = data_scan['resource']
            return resource
        except:
            print("An error occurred while uploading the file")
            error_notification = win10toast.ToastNotifier()
            error_notification.show_toast(f'Error in the {detected_file} scan', "An error occurred while uploading the file", duration=10, icon_path="icon.ico")
            old_files = os.listdir()
            return None

    def get_report(self, file, resource):
        try:
            url_report = 'https://www.virustotal.com/vtapi/v2/file/report'
            params_report = {'apikey':self.api, 'resource': resource}
            while True:
                response_report = requests.get(url_report, params=params_report)
                report_data = response_report.json()
                response_code = report_data['response_code']
                if response_code == 0:
                    print("The file is queued")
                    time.sleep(10)
                elif response_code == 1:
                    positives = report_data['positives']
                    positives = int(positives)
                    if positives == 0:
                        result = f"No antivirus has detected any malware in {detected_file}"
                    else:
                        result = f"{positives} antivirus have detected malware in this file" 
                    old_files = os.listdir()
                    break
                else:
                    result = "Unexpected error"
                    break
            return result
        except:
            return "An error occurred while getting the report"
            old_files = os.listdir()

old_files = os.listdir()
while True:
    new_files = os.listdir()
    if old_files != new_files:
        detected_file = set(old_files) ^ set(new_files)
        detected_file = str(detected_file)
        detected_file = detected_file.replace("{", "")
        detected_file = detected_file.replace("}", "")
        detected_file = detected_file.replace("'", "")
        if detected_file in os.listdir():
            print("New file detected")
            time.sleep(5)
            file = virustotal()
            file_resource = file.scan_file(detected_file)
            if file_resource is None:
                print("Unable to get the resource")
                old_files = os.listdir()
            else:
                print(f"{detected_file} has been scanned")
                file_resource = str(file_resource)
                result = file.get_report(detected_file, file_resource)
                print(result)
                scan_notification = win10toast.ToastNotifier()
                scan_notification.show_toast(f'New scan completed for {detected_file}', result, duration=10, icon_path="icon.ico")
                old_files = os.listdir()
        else:
            old_files = os.listdir()
    else:
        pass  


    

