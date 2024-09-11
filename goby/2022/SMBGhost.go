package exploits

import (
	"bytes"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"time"
)

func init() {
	expJson := `{
    "Name": "Windows SMBv3 Client/Server Remote Code Execution Vulnerability",
    "Description": "A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.",
    "Product": "xxx",
    "Homepage": "xxx",
    "DisclosureDate": "2020-03-12",
    "Author": "gaopeng2@baimaohui.net",
    "FofaQuery": "app=\"appst\"",
    "GobyQuery": "app=\"appst\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": null,
    "RealReferences": [
        "http://packetstormsecurity.com/files/156731/CoronaBlue-SMBGhost-Microsoft-Windows-10-SMB-3.1.1-Proof-Of-Concept.html",
        "http://packetstormsecurity.com/files/156732/Microsoft-Windows-SMB-3.1.1-Remote-Code-Execution.html",
        "http://packetstormsecurity.com/files/156980/Microsoft-Windows-10-SMB-3.1.1-Local-Privilege-Escalation.html",
        "http://packetstormsecurity.com/files/157110/SMBv3-Compression-Buffer-Overflow.html",
        "http://packetstormsecurity.com/files/157901/Microsoft-Windows-SMBGhost-Remote-Code-Execution.html",
        "http://packetstormsecurity.com/files/158054/SMBleed-SMBGhost-Pre-Authentication-Remote-Code-Execution-Proof-Of-Concept.html",
        "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0796"
    ],
    "HasExp": null,
    "ExpParams": null,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": null,
    "CVEIDs": [
        "CVE-2020-0796"
    ],
    "CVSSScore": "10.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "PocId": "10487"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			fmt.Println(hostinfo.HostInfo)
			conn, err := net.DialTimeout("tcp", hostinfo.HostInfo, 2*time.Second)
			if err != nil {
				//fmt.Println(ip + " Timeout")
			} else {
				defer conn.Close()
				conn.Write([]byte(pktStr()))

				buff := make([]byte, 1024)
				err = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := conn.Read(buff)
				if err != nil {
					//fmt.Println(err.Error()) // Profound analysis
				}

				if bytes.Contains([]byte(buff[:n]), []byte("Public")) == true {
					//if runtime.GOOS=="windows" {
					//	fmt.Println(ip + " CVE-2020-0796 SmbGhost Vulnerable")
					//} else
					//{fmt.Println("\033[35m"+ip + " CVE-2020-0796 SmbGhost Vulnerable"+"\033[0m")}
					return true
				} else {
					//fmt.Println(ip + " Not Vulnerable")
					return false
				}
			}
			return false
		},
		nil,
	))
}
func pktStr() string {
	return "\x00" + // session
		"\x00\x00\xc0" + // legth

		"\xfeSMB@\x00" + // protocol

		//[MS-SMB2]: SMB2 NEGOTIATE Request
		//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5

		"\x00\x00" +
		"\x00\x00" +
		"\x00\x00" +
		"\x00\x00" +
		"\x1f\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +

		// [MS-SMB2]: SMB2 NEGOTIATE_CONTEXT
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7

		"$\x00" +
		"\x08\x00" +
		"\x01\x00" +
		"\x00\x00" +
		"\x7f\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"x\x00" +
		"\x00\x00" +
		"\x02\x00" +
		"\x00\x00" +
		"\x02\x02" +
		"\x10\x02" +
		"\x22\x02" +
		"$\x02" +
		"\x00\x03" +
		"\x02\x03" +
		"\x10\x03" +
		"\x11\x03" +
		"\x00\x00\x00\x00" +

		// [MS-SMB2]: SMB2_PREAUTH_INTEGRITY_CAPABILITIES
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5

		"\x01\x00" +
		"&\x00" +
		"\x00\x00\x00\x00" +
		"\x01\x00" +
		"\x20\x00" +
		"\x01\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00" +

		// [MS-SMB2]: SMB2_COMPRESSION_CAPABILITIES
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/78e0c942-ab41-472b-b117-4a95ebe88271

		"\x03\x00" +
		"\x0e\x00" +
		"\x00\x00\x00\x00" +
		"\x01\x00" + //CompressionAlgorithmCount
		"\x00\x00" +
		"\x01\x00\x00\x00" +
		"\x01\x00" + //LZNT1
		"\x00\x00" +
		"\x00\x00\x00\x00"
}

// generate by genpoc: D:\Goby\gobypoc\goby-cmd.exe -mode genpoc -CVEID CVE-2020-0796 -exportFile D:\Goby\gobypoc\POC/SMBGhost.go false
