import tkinter as tk
from tkinter import ttk, messagebox
import user
import crypto
import issuer
import json

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("License System")
        self.geometry("800x600")
        self.user = user.User()
        self.crypto = crypto.Crypto()
        self.issuer = issuer.Issuer()
        self.LICENSECODE = ''
        self.LICENSEJSON = json.dumps({'':''})

        self.create_widgets()

    def create_widgets(self):
        left_frame = tk.Frame(self, width=400, height=600)
        right_frame = tk.Frame(self, width=400, height=600)
        
        left_frame.pack(side='left', fill='both', expand=True)
        right_frame.pack(side='right', fill='both', expand=True)

        button_frame = tk.Frame(left_frame)
        button_frame.pack(pady=10)

        self.identity_button = tk.Button(button_frame, text="获取身份码", command=self.show_identity)
        self.identity_button.pack(side='left', padx=5)

        self.activation_button = tk.Button(button_frame, text="获取激活码", command=self.show_activation_code)
        self.activation_button.pack(side='left', padx=5)

        tk.Label(left_frame, text="用户名:").pack(pady=5)
        self.username_entry = tk.Entry(left_frame)
        self.username_entry.pack(pady=5)

        tk.Label(left_frame, text="组别:").pack(pady=5)
        self.group_var = tk.StringVar()
        self.group_combobox = ttk.Combobox(left_frame, textvariable=self.group_var)
        self.group_combobox['values'] = ('30天试用期', '360天用户', '720天用户', '永久高级用户')
        self.group_combobox.pack(pady=5)

        tk.Label(left_frame, text="身份码:").pack(pady=5)
        self.identity_text_box = tk.Text(left_frame, wrap='word', width=40, height=10)
        self.identity_text_box.pack(pady=5, padx=20)
        self.identity_text_box.config(state=tk.DISABLED)

        tk.Label(left_frame, text="激活码:").pack(pady=5)
        self.activation_text_box = tk.Text(left_frame, wrap='word', width=40, height=10)
        self.activation_text_box.pack(pady=5, padx=20)
        self.activation_text_box.config(state=tk.DISABLED)

        tk.Label(right_frame, text="输入激活码:").pack(pady=5)
        self.verify_entry = tk.Entry(right_frame)
        self.verify_entry.pack(pady=5)

        self.verify_button = tk.Button(right_frame, text="验证激活码", command=self.verify_activation_code)
        self.verify_button.pack(pady=10)

        self.info_labels = ["用户", "用户组", "授权人", "起始时间", "过期时间"]
        self.info_text_boxes = []

        for label in self.info_labels:
            tk.Label(right_frame, text=label + ":").pack(pady=5)
            text_box = tk.Text(right_frame, wrap='word', width=40, height=2)
            text_box.pack(pady=5, padx=20)
            text_box.config(state=tk.DISABLED)
            self.info_text_boxes.append(text_box)

    def show_identity(self):
        identity = self.user.getIdentityNumber()
        self.identity_text_box.config(state=tk.NORMAL)
        self.identity_text_box.delete(1.0, tk.END)
        self.identity_text_box.insert(tk.END, identity)
        self.identity_text_box.config(state=tk.DISABLED)

    def show_activation_code(self):
        username = self.username_entry.get()
        group = self.group_var.get()

        if not username or not group:
            messagebox.showwarning("输入错误", "请填写用户名和选择组别。")
            return
        
        # 映射组别到代码
        group_codes = {
            '30天试用期': 'A',
            '360天用户': 'B',
            '720天用户': 'C',
            '永久高级用户': 'D',
        }

        # 走流程
        group_code = group_codes.get(group, '')
        identity = self.user.getIdentityNumber()
        user_info = json.dumps({
            'user': crypto.b64encode(username.encode('UTF-8')).decode('utf-8'),
            'level': crypto.b64encode(group.encode('UTF-8')).decode('utf-8')
        })
        lic_req = self.user.licenseRequest(identity, user_info)
        license_json = self.issuer.license_generate(lic_req, group_code)
        self.LICENSEJSON = license_json
        license_code = self.crypto.encode_json_to_base64(license_json)
        activation_code = license_code
        self.LICENSECODE = license_code
        #print(self.LICENSEJSON)
        
        self.activation_text_box.config(state=tk.NORMAL)
        self.activation_text_box.delete(1.0, tk.END)
        self.activation_text_box.insert(tk.END, activation_code)
        self.activation_text_box.config(state=tk.DISABLED)

    def verify_activation_code(self):
        activation_code = self.verify_entry.get()
        
        # 走验签流程
        activation_license = self.crypto.decode_base64_to_json(activation_code)
        pt_license = ''
        try: 
            dic_Lic = json.loads(activation_license)
            pt_license = self.crypto.AES_Decrypt(activation_license) # 得到字符串
            trial = self.crypto.RSA_PSS_verify(pt_license, dic_Lic["signature"])
            del dic_Lic['signature']
            del dic_Lic['iv']
            del dic_Lic['ciphertext']
            dic_Lic = {key: (crypto.b64decode(value.encode('utf-8'))).decode('utf-8') for key, value in dic_Lic.items()}
        except TypeError:
            trial = False

        if trial:
            user_info = [dic_Lic['licensee'], dic_Lic['level'], dic_Lic['licenser'], dic_Lic['issue_day'], dic_Lic['expiry_date']]
            for text_box, info in zip(self.info_text_boxes, user_info):
                text_box.config(state=tk.NORMAL)
                text_box.delete(1.0, tk.END)
                text_box.insert(tk.END, info)
                text_box.config(state=tk.DISABLED)
        else:
            messagebox.showerror("错误", "激活码无效!")