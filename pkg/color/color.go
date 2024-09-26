package color

import (
	"fmt"
)

const (
	Red    = "\x1b[31m"
	Green  = "\x1b[32m"
	Yellow = "\x1b[33m"
	Bule   = "\x1b[34m"
	Purple = "\x1b[35m"
	Cyan   = "\x1b[36m"
	White  = "\x1b[37m"
)

func PrintRed(str string) string {
	return Red + str + White
}

func PrintGreen(str string) string {
	return Green + str + White
}

func PrintYellow(str string) string {
	return Yellow + str + White
}

func PrintBule(str string) string {
	return Bule + str + White
}

func PrintPurple(str string) string {
	return Purple + str + White
}

func PrintCyan(str string) string {
	return Cyan + str + White
}

func StatusCodeColor(code int) string {
	if code == 200 {
		return PrintGreen(fmt.Sprint(code))
	} else if code >= 300 && code < 400 {
		return PrintYellow(fmt.Sprint(code))
	} else if code >= 400 && code < 500 {
		return PrintPurple(fmt.Sprint(code))
	} else {
		return PrintRed(fmt.Sprint(code))
	}
}

func WithSeverityColors(severity string) string {
	switch severity {
	case "low":
		return PrintBule(severity)
	case "medium":
		return PrintYellow(severity)
	case "high":
		return PrintRed(severity)
	case "critical":
		return PrintPurple(severity)
	default:
		return PrintBule(severity)
	}
}
