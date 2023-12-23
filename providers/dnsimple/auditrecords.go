package dnsimple

import (
	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/rejectif"
)

// AuditRecords returns a list of errors corresponding to the records
// that aren't supported by this provider.  If all records are
// supported, an empty list is returned.
func AuditRecords(records []*models.RecordConfig) []error {
	a := rejectif.Auditor{}

	a.Add("MX", rejectif.MxNull) // Last verified 2023-03

	// Documentation: <https://support.dnsimple.com/articles/txt-record/>
	//
	// If you provide quotes inside the string, they assume it's pre-chunked;
	// If you just provide the string without quotes inside the payload, they split.
	// They explicitly do split, to handle DKIM keys, but impose their own
	// arbitrary length limit of 1000 characters, per documentation.
	a.Add("TXT", rejectif.TxtLongerThan(1000)) // Last verified 2023-12

	a.Add("TXT", rejectif.TxtHasTrailingSpace) // Last verified 2023-03

	a.Add("TXT", rejectif.TxtHasUnpairedDoubleQuotes) // Last verified 2023-03

	a.Add("TXT", rejectif.TxtIsEmpty) // Last verified 2023-03

	return a.Audit(records)
}
