package secrets

var ExpirationRanges = map[int]string{
	30:     "30 seconds",
	60:     "1 minute",
	300:    "5 minutes",
	900:    "15 minutes",
	1800:   "30 minutes",
	3600:   "1 hour",
	7200:   "2 hours",
	10800:  "3 hours",
	21600:  "6 hours",
	43200:  "12 hours",
	86400:  "1 day",
	259200: "3 days",
	432000: "5 days",
	604800: "1 week",
}
