# -*- coding: utf-8 -*-
import wmi
import crypto
import json

class User:
    def __init__(self):
        self.userCrypto = crypto.Crypto()
        self.s = wmi.WMI()  
    # cpu序列号
    def get_CPU_info(self):
        cpu = []
        cp = self.s.Win32_Processor()
        for u in cp:
            cpu.append(
                {
                    "Name": u.Name,
                    "Serial Number": u.ProcessorId,
                    "CoreNum": u.NumberOfCores
                }
            )
        return cpu
 
    # 硬盘
    def get_disk_info(self):
        disk = []
        for pd in self.s.Win32_DiskDrive():
            disk.append(
                {
                    "Serial": self.s.Win32_PhysicalMedia()[0].SerialNumber.lstrip().rstrip(),  # 获取硬盘序列号，调用另外一个win32 API
                    "ID": pd.deviceid,
                    "Caption": pd.Caption,
                    "size": str(int(float(pd.Size)/1024/1024/1024))
                }
            )
        return disk
 
    # mac
    def get_network_info(self):
        network = []
        for nw in self.s.Win32_NetworkAdapterConfiguration():
            if nw.MacAddress != None:
                network.append(
                    {
                        "MAC": nw.MacAddress,
                        "ip": nw.IPAddress
                    }
                )
        return network
 
    # 主板
    def get_mainboard_info(self):
        mainboard = []
        for board_id in self.s.Win32_BaseBoard():
            mainboard.append(board_id.SerialNumber.strip().strip('.'))
        return mainboard
 
    # 唯一识别码
    def getIdentityNumber(self):
        a = self.get_network_info()
        b = self.get_CPU_info()
        c = self.get_disk_info()
        d = self.get_mainboard_info()
        Identitycode = ""
        Identitycode = Identitycode + a[0]['MAC'] + b[0]['Serial Number'] + c[0]['Serial'] + d[0]
        return Identitycode

    # json + json -> json
    def licenseRequest(self, code, user_info):
        # user_info is a json too
        cipher_text =  self.userCrypto.AES_Encrypt(code)
        dict1 = json.loads(cipher_text)
        dict2 = json.loads(user_info) # user_info has been base64-encrypted
        dict1.update(dict2)
        lic_Req = json.dumps(dict1)
        return lic_Req
    

    def licenseVerify(self, license_json):
        license_info = json.loads(license_json)
        ct_decrypted = crypto.b64decode(license_info['ct'].encode('UTF-8'))
        return self.userCrypto.RSA_PSS_verify(ct_decrypted, crypto.b64decode(license_info['signature']))

    def licenseTXT(self, license_json):
        try:        
            license_info = json.loads(license_json)
            labels = ["licenser", "licensee", "level", "issue_date", "expiry_date"]
        #    if len(license_info) != 5:
        #    raise ValueError("证书错误")
            
            with open('LICENSE.TXT', 'w') as file:
                for label in labels:
                    if label in license_info:
                        file.write(f"{label}: {crypto.b64decode(license_info[label])}\n")
        except json.JSONDecodeError:
            print("Invalid JSON format.")
