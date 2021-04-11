# Author: Klaus
# Date: 2021/4/11 15:04
from flask import Flask, request, abort
from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.exceptions import InvalidSignatureException
from wechatpy.enterprise.exceptions import InvalidCorpIdException
from wechatpy.enterprise import parse_message, create_reply
from wechatpy.enterprise import WeChatClient
import requests, random, string, time, os
import hashlib
from urllib.parse import urlencode

#环境变量
corpid = os.getenv("coprid")
corpsecrete = os.getenv("corpsecrete")
Token = os.getenv("Token")
EncodingAESKey = os.getenv("EncodingAESKey")
app_key = os.getenv("app_key")


client = WeChatClient(corpid, corpsecrete)
app = Flask(__name__)


def ran_str():
    salt = ''.join(random.sample(string.ascii_letters + string.digits, 6))
    return salt


def jianquan(params):
    # 处理参数
    before_sign = ''
    params_new = {}
    for key in sorted(params):
        params_new[key] = params[key]
    before_sign += urlencode(params_new)
    before_sign += f"&app_key={app_key}"
    # 对获得的before_sign进行MD5加密
    sign = hashlib.md5(before_sign.encode("utf-8")).hexdigest().upper()
    # 将请求签名添加进参数字典
    return sign

def process_message(msg):
    update_text = msg
    quests = update_text[1:]
    params = {
        "app_id": "2160905959",
        "session": "2333",
        "question": quests,
        "time_stamp": int(time.time()),
        "nonce_str": ran_str()

    }
    params["sign"] = jianquan(params)
    chat_url = "https://api.ai.qq.com/fcgi-bin/nlp/nlp_textchat"
    r = requests.post(chat_url, params)
    talk_text = r.json()["data"]["answer"]
    print(talk_text)
    return talk_text

@app.route("/wechat", methods=['GET', 'POST'])
def wechat():
    signature = request.args.get('msg_signature', '')
    timestamp = request.args.get('timestamp', '')
    nonce = request.args.get('nonce', '')

    crypto = WeChatCrypto(Token, EncodingAESKey, corpid)
    if request.method == 'GET':
        echo_str = request.args.get('echostr', '')
        try:
            echo_str = crypto.check_signature(
                signature,
                timestamp,
                nonce,
                echo_str
            )
        except InvalidSignatureException:
            abort(403)
        print(echo_str)
        return echo_str

    else:
        try:
            msg = crypto.decrypt_message(
                request.data,
                signature,
                timestamp,
                nonce
            )
        except (InvalidSignatureException, InvalidCorpIdException):
            abort(403)
        msg = parse_message(msg)
        user_name = msg.source
        if msg.type == 'text':
            message = msg.content
            rep = process_message(message)
            reply = create_reply(rep, msg).render()
            res = crypto.encrypt_message(reply, nonce, timestamp)
            print(res)
            return res

if __name__ == "__main__":
    app.run('0.0.0.0', 5001, debug=False)
