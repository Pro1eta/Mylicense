import crypto
import json
from datetime import datetime, timedelta

class Issuer:
    def __init__(self):
        self.IssuerCrypto = crypto.Crypto()

    def license_generate(self, lic_req, group_code):
        b64 = json.loads(lic_req)
        pt = self.IssuerCrypto.AES_Decrypt(lic_req)
        licensee = (crypto.b64decode(b64['user'].encode('utf-8'))).decode('utf-8')
        level = (crypto.b64decode(b64['level'].encode('utf-8'))).decode('utf-8')

        t = datetime.now()
        if group_code == 'A':
            time_str = t + timedelta(days=30)
        elif group_code == 'B':
            time_str = t + timedelta(days=360)
        elif group_code == 'C':
            time_str = t + timedelta(days=720)
        else:
            time_str = t + timedelta(days=365*2)  

        info_dic = {'licensee':licensee, 'licenser':'BUPT', 'level':level, 'issue_day':t.strftime("%Y-%m-%d"), 'expiry_date':time_str.strftime("%Y-%m-%d")}
        if group_code == 'D':
            info_dic['expiry_date'] = '永久'

        # new plaint text
        pt_new = pt + info_dic['licensee'] + info_dic['licenser'] + info_dic['level'] + info_dic['issue_day'] + info_dic['expiry_date'] 
        
        info_dic = {key: (crypto.b64encode(value.encode('utf-8'))).decode('utf-8') for key, value in info_dic.items()}

        signature_lic =  json.dumps({'signature':self.IssuerCrypto.RSA_PSS_signature(pt_new)})
        ct_lic = self.IssuerCrypto.AES_Encrypt(pt_new) # 仅仅通过 AES 加密(其实已经有base64编码环节)获得了密文, 没有再再次 base64 编码
        info_lic = json.dumps(info_dic) # 经过了 base64 编码

        #Json of Licence
        dict1 = json.loads(signature_lic)
        dict2 = json.loads(ct_lic)
        dict3 = json.loads(info_lic) 
        dict1.update(dict2)
        dict1.update(dict3)

        license_json = json.dumps(dict1)
        return license_json